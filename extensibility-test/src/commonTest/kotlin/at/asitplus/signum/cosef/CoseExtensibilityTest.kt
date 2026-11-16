@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.cosef

import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.mac.mac
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.*
import kotlinx.serialization.cbor.*
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Instant

@Serializable
private data class NestedValue(val scope: String, val version: Int)

@Serializable
private data class Claims(
    @CborLabel(1) override val issuer: String,
    @CborLabel(6) @Serializable(with = InstantLongSerializer::class) override val issuedAt: Instant,
) : CwtClaims

@Serializable
private data class Protected(
    @CborLabel(1) override val algorithm: CoseAlgorithm,
    @CborLabel(-65537) val required: NestedValue,
    @SerialName("application") val application: String,
    @CborLabel(33) @Serializable(with = X5ChainSerializer::class) override val certificateChain: List<ByteArray>? = null,
    @CborLabel(2) @Serializable(with = CriticalHeadersSerializer::class) override val criticalHeaders: List<CoseHeaderLabel>? = null,
    @CborLabel(15) override val cwtClaims: Claims? = null,
) : CoseHeader

@Serializable
private data class Unprotected(
    @SerialName("route") val route: String,
    @CborLabel(4) @ByteString override val kid: ByteArray? = null,
) : CoseHeader

@Serializable
private data class Body(@CborLabel(16) override val type: String) : CoseHeader

@Serializable
private data class Payload(val name: String)

@Serializable
private data class NestedMessages(val sign: CoseSign1<Protected, Unprotected, Payload>, val mac: CoseMac0<Protected, Unprotected, Payload>)

@Serializable
@CborArray
private data class ReceivedEnvelope(
    @ByteString val protected: ByteArray,
    val unprotected: Protected,
    @ByteString val payload: ByteArray?,
    @ByteString val authentication: ByteArray,
)

private fun headers(algorithm: CoseAlgorithm) = Protected(algorithm, NestedValue("wallet", 1), "vck", listOf(byteArrayOf(1, 2)), cwtClaims = Claims("issuer", Instant.fromEpochSeconds(42)))

private class CountingSigner(private val delegate: Signer) : Signer by delegate {
    var calls = 0
    override suspend fun sign(data: SignatureInput): SignatureResult<*> { calls++; return delegate.sign(data) }
}

private class CountingPayloadSerializer : KSerializer<Payload> by Payload.serializer() {
    var calls = 0
    override fun serialize(encoder: Encoder, value: Payload) { calls++; Payload.serializer().serialize(encoder, value) }
}

val CoseExtensibilityTest by matrixSuite {
    Signum.installSupreme()

    "External required header models sign, decode, verify, and compose" {
        val signer = Signer.Ephemeral { ec {} }
        val aad = byteArrayOf(7, 8)
        val sign = CoseSigner(signer).sign1(headers(CoseAlgorithm.Signature.ES256), Unprotected("peer"), Payload("alice"), externalAad = aad)
        val bytes = coseCompliantSerializer.encodeToByteArray(sign)
        val raw = CoseSign1.Raw<Unprotected>(bytes)
        val decoded = raw.typed<Protected, Payload>()
        decoded.protectedHeader.required shouldBe NestedValue("wallet", 1)
        decoded.protectedHeader.certificateChain!!.single() shouldBe byteArrayOf(1, 2)
        decoded.protectedHeader.cwtClaims shouldBe Claims("issuer", Instant.fromEpochSeconds(42))
        decoded.unprotectedHeader.route shouldBe "peer"
        decoded.payload shouldBe Payload("alice")
        signer.makeVerifier().verify(decoded.signatureInput(aad), decoded.signature) shouldBe SignatureVerifier.Success
        shouldThrowAny { signer.makeVerifier().verify(decoded.signatureInput(), decoded.signature) }
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe bytes

        val key = ByteArray(32) { it.toByte() }
        val mac = CoseMacCreator(CoseAlgorithm.MAC.HS256, key).mac0(headers(CoseAlgorithm.MAC.HS256), Unprotected("peer"), Payload("alice"), externalAad = aad)
        val nested = coseCompliantSerializer.encodeToByteArray(NestedMessages(sign, mac))
        val roundtrip = coseCompliantSerializer.decodeFromByteArray(NestedMessages.serializer(), nested)
        CoseAlgorithm.MAC.HS256.mac(key, roundtrip.mac.macInput(aad)) shouldBe roundtrip.mac.tag
        coseCompliantSerializer.encodeToByteArray(roundtrip) shouldBe nested
    }

    "Attached empty and detached payloads authenticate the same bytes but retain different envelopes" {
        val signer = Signer.Ephemeral { ec {} }
        val coseSigner = CoseSigner(signer)
        val attached = coseSigner.sign1(headers(CoseAlgorithm.Signature.ES256), byteArrayOf())
        val detached = coseSigner.sign1(headers(CoseAlgorithm.Signature.ES256), byteArrayOf(), detached = true)
        val decoded = CoseSign1<Protected, EmptyCoseHeader, ByteArray>(coseCompliantSerializer.encodeToByteArray(detached))
        attached.isDetached shouldBe false
        decoded.isDetached shouldBe true
        decoded.payload shouldBe null
        detached.detachedPayload shouldBe byteArrayOf()
        decoded.detachedPayload shouldBe null
        shouldThrowAny { decoded.signatureInput() }
        attached.signatureInput() shouldBe decoded.signatureInput(detachedPayload = byteArrayOf())
        signer.makeVerifier().verify(decoded.signatureInput(detachedPayload = byteArrayOf()), decoded.signature) shouldBe SignatureVerifier.Success
        val key = ByteArray(32)
        val mac = CoseMacCreator(CoseAlgorithm.MAC.HS256, key).mac0(headers(CoseAlgorithm.MAC.HS256), byteArrayOf(), detached = true)
        val decodedMac = CoseMac0<Protected, EmptyCoseHeader, ByteArray>(coseCompliantSerializer.encodeToByteArray(mac))
        decodedMac.isDetached shouldBe true
        shouldThrowAny { decodedMac.macInput() }
        CoseAlgorithm.MAC.HS256.mac(key, decodedMac.macInput(detachedPayload = byteArrayOf())) shouldBe decodedMac.tag
        val serializer = CountingPayloadSerializer()
        val typedDetached = coseSigner.sign1(headers(CoseAlgorithm.Signature.ES256), Payload("external"), serializer, Protected.serializer(), detached = true)
        serializer.calls shouldBe 1
        val received = CoseSign1<Protected, EmptyCoseHeader, Payload>(coseCompliantSerializer.encodeToByteArray(typedDetached))
        signer.makeVerifier().verify(received.signatureInput(detachedPayload = typedDetached.detachedPayload), received.signature) shouldBe SignatureVerifier.Success
    }

    "Both empty protected representations retain real signature and MAC validity" {
        val signer = Signer.Ephemeral { ec {} }
        val payload = byteArrayOf(1, 2, 3)
        val key = ByteArray(32)
        for (protected in listOf(byteArrayOf(), byteArrayOf(0xA0.toByte()))) {
            val input = COSE.sign1StructureInput(protected, payload = payload)
            val signature = signer.sign(input).signature
            val encoded = coseCompliantSerializer.encodeToByteArray(ReceivedEnvelope(protected, headers(CoseAlgorithm.Signature.ES256), payload, signature.coseBytes))
            val decoded = CoseSign1<EmptyCoseHeader, Protected, ByteArray>(encoded)
            signer.makeVerifier().verify(decoded.signatureInput(), decoded.signature) shouldBe SignatureVerifier.Success
            coseCompliantSerializer.encodeToByteArray(decoded) shouldBe encoded

            val mac = CoseAlgorithm.MAC.HS256.mac(key, COSE.mac0StructureInput(protected, payload = payload))
            val macEncoded = coseCompliantSerializer.encodeToByteArray(ReceivedEnvelope(protected, headers(CoseAlgorithm.MAC.HS256), payload, mac))
            val macDecoded = CoseMac0<EmptyCoseHeader, Protected, ByteArray>(macEncoded)
            CoseAlgorithm.MAC.HS256.mac(key, macDecoded.macInput()) shouldBe macDecoded.tag
            coseCompliantSerializer.encodeToByteArray(macDecoded) shouldBe macEncoded
        }
    }

    "Mismatches, conflicts, and unprocessed critical parameters fail before signing" {
        val signer = CountingSigner(Signer.Ephemeral { ec {} })
        val signing = CoseSigner(signer)
        shouldThrowAny { signing.sign1(headers(CoseAlgorithm.Signature.RS256), Payload("x")) }
        val wrongCurve = CountingSigner(Signer.Ephemeral { ec { curve = ECCurve.SECP_384_R_1 } })
        shouldThrowAny { CoseSigner(wrongCurve).sign1(headers(CoseAlgorithm.Signature.ES256), Payload("x")) }
        wrongCurve.calls shouldBe 0
        shouldThrowAny { signing.sign1(headers(CoseAlgorithm.Signature.ES256), headers(CoseAlgorithm.Signature.ES256), Payload("x")) }
        val critical = headers(CoseAlgorithm.Signature.ES256).copy(criticalHeaders = listOf(CoseHeaderLabel.Numeric(-65537)))
        shouldThrowAny { signing.sign1(critical, Payload("x")) }
        signer.publicKey.coseKid = byteArrayOf(1)
        shouldThrowAny { signing.sign1(headers(CoseAlgorithm.Signature.ES256), Unprotected("peer", byteArrayOf(2)), Payload("x")) }
        signer.calls shouldBe 0
        signing.sign1(critical, Payload("x"), processCritical = { it == CoseHeaderLabel.Numeric(-65537) })
        signer.calls shouldBe 1
        shouldThrowAny { CoseMacCreator(CoseAlgorithm.MAC.HS256, ByteArray(32)).mac0(headers(CoseAlgorithm.MAC.HS512), Payload("x")) }
    }

    "Multiple EC and RSA signatures share one payload serialization and preserve order" {
        val signers = listOf(Signer.Ephemeral { ec {} }, Signer.Ephemeral { rsa { bits = 2048; digest = Digest.SHA256; padding = RsaAlgorithm.Padding.PSS } })
        val parameters = listOf(CoseAlgorithm.Signature.ES256, CoseAlgorithm.Signature.PS256).map { CoseSignatureParameters(headers(it), Unprotected("peer")) }
        val serializer = CountingPayloadSerializer()
        val signed = CoseSigner(signers).sign(Body("application/test"), EmptyCoseHeader, Payload("alice"), parameters, serializer, Body.serializer(), EmptyCoseHeader.serializer())
        serializer.calls shouldBe 1
        val bytes = coseCompliantSerializer.encodeToByteArray(signed)
        val decoded = CoseSign.Raw<EmptyCoseHeader, Unprotected>(bytes).typed<Body, Protected, Payload>()
        for (index in signers.indices) {
            val signature = decoded.signatures[index]
            val parsed = decoded.signature(index)
            signers[index].makeVerifier().verify(decoded.signatureInput(index), parsed) shouldBe SignatureVerifier.Success
            decoded.signatures[index].raw.plainProtectedHeader shouldBe signed.signatures[index].raw.plainProtectedHeader
        }
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe bytes
        // Every signature covers the body's protected bytes; only one covers each signer's protected bytes.
        decoded.raw.plainProtectedHeader[decoded.raw.plainProtectedHeader.lastIndex] = 'X'.code.toByte()
        for (index in signers.indices) {
            val signature = decoded.signatures[index]
            shouldThrowAny { signers[index].makeVerifier().verify(decoded.signatureInput(index), COSE.getSignature(signature.raw.plainSignature, signature.protectedHeader)) }
        }
        val signerTampered = CoseSign.Raw<EmptyCoseHeader, Unprotected>(bytes).typed<Body, Protected, Payload>()
        signerTampered.signatures[0].raw.plainProtectedHeader[2] = 0x27
        shouldThrowAny { signers[0].makeVerifier().verify(signerTampered.signatureInput(0), COSE.getSignature(signerTampered.signatures[0].raw.plainSignature, signerTampered.signatures[0].protectedHeader)) }
        signers[1].makeVerifier().verify(signerTampered.signatureInput(1), COSE.getSignature(signerTampered.signatures[1].raw.plainSignature, signerTampered.signatures[1].protectedHeader)) shouldBe SignatureVerifier.Success
        val single = CoseSigner(signers[0]).sign(Body("application/test"), EmptyCoseHeader, Payload("alice"), parameters.take(1))
        val sign1 = CoseSigner(signers[0]).sign1(headers(CoseAlgorithm.Signature.ES256), Unprotected("peer"), Payload("alice"))
        single.signatureInput(0).contentEquals(sign1.signatureInput()) shouldBe false
    }

    "All multi-signature parameters are checked before the first signer runs" {
        val signer = CountingSigner(Signer.Ephemeral { ec {} })
        val parameters = listOf(CoseAlgorithm.Signature.ES256, CoseAlgorithm.Signature.RS256).map { CoseSignatureParameters(headers(it)) }
        shouldThrowAny { CoseSigner(signer).sign(EmptyCoseHeader, EmptyCoseHeader, Payload("alice"), parameters) }
        signer.calls shouldBe 0
    }

    "Signer failures and cancellation propagate" {
        val original = Signer.Ephemeral { ec {} }
        val failure = CancellationException("cancel signing")
        val cancelling = object : Signer by original { override suspend fun sign(data: SignatureInput): SignatureResult<*> = throw failure }
        shouldThrow<CancellationException> { CoseSigner(cancelling).sign1(headers(CoseAlgorithm.Signature.ES256), Payload("x")) } shouldBe failure
    }
}
