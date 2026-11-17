@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum

import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.*
import kotlinx.serialization.cbor.CborLabel
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@Serializable
private data class JoseHeader(
    @SerialName("alg") override val algorithm: JwsAlgorithm,
    @SerialName("kid") override val keyId: String? = null,
) : JwsHeader {
    @Transient override val type: String? = null
    @Transient override val contentType: String? = null
    @Transient override val certificateChain: CertificateChain? = null
    @Transient override val jsonWebKey: JsonWebKey? = null
    @Transient override val jsonWebKeySetUrl: String? = null
    @Transient override val certificateUrl: String? = null
    @Transient override val certificateSha1Thumbprint: ByteArray? = null
    @Transient override val certificateSha256Thumbprint: ByteArray? = null
    @Transient override val crit: List<String>? = null
}

@Serializable
private data class CoseProtected(
    @CborLabel(1) override val algorithm: CoseAlgorithm,
)
    : CoseHeader

@Serializable
private data class CoseUnprotected(@CborLabel(4) override val kid: ByteArray? = null) : CoseHeader {
    override fun equals(other: Any?) = other is CoseUnprotected && kid.contentEquals(other.kid)
    override fun hashCode() = kid?.contentHashCode() ?: 0
}

private class ObservedSigner(private val delegate: Signer) : Signer by delegate {
    var calls = 0
    override suspend fun sign(data: SignatureInput): SignatureResult<*> {
        calls++
        return delegate.sign(data)
    }
}

private data class SelectionCase(val name: String, val ids: List<String?>, val requested: String?, val selected: Int?) {
    override fun toString() = name
}

val ApiParityTest by matrixSuite {
    Signum.installSupreme()

    data(listOf(
        SelectionCase("sole labeled key without request", listOf("a"), null, 0),
        SelectionCase("sole unlabeled key without request", listOf(null), null, 0),
        SelectionCase("sole unlabeled key with application ID", listOf(null), "a", 0),
        SelectionCase("sole conflicting ID", listOf("a"), "b", null),
        SelectionCase("same algorithm selects first ID", listOf("a", "b"), "a", 0),
        SelectionCase("same algorithm selects second ID", listOf("a", "b"), "b", 1),
        SelectionCase("registration order does not select key", listOf("b", "a"), "a", 1),
        SelectionCase("missing ID is ambiguous", listOf("a", "b"), null, null),
        SelectionCase("unknown ID", listOf("a", "b"), "c", null),
        SelectionCase("duplicate IDs are ambiguous", listOf("a", "a"), "a", null),
        SelectionCase("exact match beats unlabeled", listOf(null, "a"), "a", 1),
        SelectionCase("unlabeled candidate cannot mask conflicting ID", listOf("a", null), "b", null),
        SelectionCase("multiple unlabeled candidates", listOf(null, null), "a", null),
    )) test { case ->
        val signers = case.ids.map { id ->
            ObservedSigner(Signer.Ephemeral { ec {} }).also {
                it.publicKey.jwkId = id
                it.publicKey.coseKid = id?.encodeToByteArray()
            }
        }
        val jose = JwsSigner(signers)
        val cose = CoseSigner(signers)
        val joseHeader = JoseHeader(JwsAlgorithm.Signature.ES256, keyId = case.requested)
        val coseHeader = CoseUnprotected(case.requested?.encodeToByteArray())
        val payload = JsonObject(mapOf("sub" to JsonPrimitive("alice")))
        val selected = case.selected
        if (selected == null) {
            shouldThrow<IllegalArgumentException> { jose.signCompact(joseHeader, payload) }
            shouldThrow<IllegalArgumentException> { cose.sign1(protectedHeader = CoseProtected(CoseAlgorithm.Signature.ES256), unprotectedHeader = coseHeader, payload = byteArrayOf(1)) }
            signers.forEach { it.calls shouldBe 0 }
        } else {
            val jws = jose.signCompact(joseHeader, payload)
            val cos = cose.sign1(protectedHeader = CoseProtected(CoseAlgorithm.Signature.ES256), unprotectedHeader = coseHeader, payload = byteArrayOf(1))
            signers[selected].makeVerifier().verify(jws.signatureInput, jws.signature) shouldBe SignatureVerifier.Success
            signers[selected].makeVerifier().verify(cos.signatureInput(), cos.signature) shouldBe SignatureVerifier.Success
            signers.map { it.calls } shouldBe signers.indices.map { if (it == selected) 2 else 0 }
            jws.header.keyId shouldBe case.requested
            cos.unprotectedHeader.kid shouldBe case.requested?.encodeToByteArray()
            val bytes = coseCompliantSerializer.encodeToByteArray(cos)
            val roundtrip = CoseSign1<CoseProtected, CoseUnprotected, ByteArray>(bytes)
            roundtrip shouldBe cos
            roundtrip.hashCode() shouldBe cos.hashCode()
        }
    }

    "same-algorithm multi-signatures select keys by ID and validate all requests first" {
        val signers = listOf("a", "b").map { id ->
            ObservedSigner(Signer.Ephemeral { ec {} }).also {
                it.publicKey.jwkId = id
                it.publicKey.coseKid = id.encodeToByteArray()
            }
        }
        val jose = JwsSigner(signers)
        val cose = CoseSigner(signers)
        val headers = listOf("b", "a")
        val jws = jose.signGeneral("payload", headers.map { JwsHeaderWrapped(JoseHeader(JwsAlgorithm.Signature.ES256, keyId = it)) })
        val cos = cose.sign(EmptyCoseHeader, EmptyCoseHeader, byteArrayOf(1), headers.map {
            CoseSignatureParameters(CoseProtected(CoseAlgorithm.Signature.ES256), CoseUnprotected(it.encodeToByteArray()))
        })
        for (i in headers.indices) {
            val verifier = signers[1 - i].makeVerifier()
            verifier.verify(jws.signatureInputs[i], jws.signatures[i]) shouldBe SignatureVerifier.Success
            verifier.verify(cos.signatureInput(i), cos.signature(i)) shouldBe SignatureVerifier.Success
        }
        val calls = signers.map { it.calls }
        shouldThrow<IllegalArgumentException> {
            jose.signGeneral("payload", listOf("a", "unknown").map { JwsHeaderWrapped(JoseHeader(JwsAlgorithm.Signature.ES256, keyId = it)) })
        }
        shouldThrow<IllegalArgumentException> {
            cose.sign(EmptyCoseHeader, EmptyCoseHeader, byteArrayOf(1), listOf("a", "unknown").map {
                CoseSignatureParameters(CoseProtected(CoseAlgorithm.Signature.ES256), CoseUnprotected(it.encodeToByteArray()))
            })
        }
        signers.map { it.calls } shouldBe calls
        val bytes = coseCompliantSerializer.encodeToByteArray(cos)
        val decoded = CoseSign.Raw<EmptyCoseHeader, CoseUnprotected>(bytes).typed<EmptyCoseHeader, CoseProtected, ByteArray>()
        decoded shouldBe cos
        decoded.hashCode() shouldBe cos.hashCode()
        val widened: CoseSign<CoseHeader, CoseHeader, CoseHeader, CoseHeader, Any?> = decoded
        widened.payload shouldBe byteArrayOf(1)
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe bytes
    }

    "shared public conversion contracts return keys directly and preserve IDs and encodings" {
        val keys = listOf(Signer.Ephemeral { ec {} }, Signer.Ephemeral { rsa { bits = 2048; digest = Digest.SHA256 } })
        for (signer in keys) {
            val publicKey = signer.publicKey
            publicKey.jwkId = "jose"
            publicKey.coseKid = byteArrayOf(1, 2)
            val jwk = publicKey.toJsonWebKey()
            val coseKey: CoseKey = publicKey.toCoseKey()
            val specialized: List<SpecializedPublicKey> = listOf(jwk, coseKey)
            specialized.forEach {
                val direct: PublicKey = it.toPublicKey()
                direct shouldBe publicKey
                it.equalsCryptographically(publicKey) shouldBe true
            }
            jwk.toPublicKey().jwkId shouldBe "jose"
            coseKey.toPublicKey().coseKid shouldBe byteArrayOf(1, 2)
            val json = joseCompliantSerializer.encodeToString(JsonWebKey.serializer(), jwk)
            joseCompliantSerializer.decodeFromString(JsonWebKey.serializer(), json).toPublicKey() shouldBe publicKey
            val bytes = coseCompliantSerializer.encodeToByteArray(coseKey)
            coseCompliantSerializer.encodeToByteArray(coseCompliantSerializer.decodeFromByteArray<CoseKey>(bytes)) shouldBe bytes
        }
        val invalid: SpecializedPublicKey = JsonWebKey()
        shouldThrow<IllegalArgumentException> { invalid.toPublicKey() }
        invalid.equalsCryptographically(keys.first().publicKey) shouldBe false
        keys.first().publicKey.equalsCryptographically(invalid) shouldBe false
        invalid.equalsCryptographically(keys.first().publicKey.toCoseKey()) shouldBe false
        shouldThrow<IllegalArgumentException> { CoseKey(CoseKeyType.EC2, keyParams = null).toPublicKey() }
        shouldThrow<IllegalArgumentException> { CoseKeyParams.SymmKeyParams(byteArrayOf(1)).toPublicKey() }
        shouldThrow<IllegalArgumentException> { CoseKeyParams.EcYBoolParams().toPublicKey() }
        shouldThrow<IllegalArgumentException> { keys.first().publicKey.toCoseKey(CoseAlgorithm.Signature.RS256) }
        shouldThrow<UnsupportedCryptoException> { EcdsaAlgorithm(Digest.SHA1).toCoseAlgorithm() }
    }

    "shared symmetric conversions support encryption and propagate conversion errors" {
        val key = SymmetricEncryptionAlgorithm.AES_128.GCM.keyFrom(ByteArray(16))
        val jwk = JsonWebKey(type = JwkType.SYM, algorithm = JweAlgorithm.A128GCMKW, k = ByteArray(16))
        val specialized: List<SpecializedSymmetricKey> = listOf(jwk, key.toCoseKey())
        val plain = byteArrayOf(1, 2, 3)
        for (encoded in specialized) {
            val direct: SymmetricKey<*> = encoded.toSymmetricKey()
            direct.algorithm shouldBe key.algorithm
            val sealed = encoded.encrypt(plain)
            sealed.decrypt(encoded) shouldBe plain
        }
        val failure = IllegalArgumentException("invalid specialized key")
        val invalid = object : SpecializedSymmetricKey {
            override fun toSymmetricKey(): SymmetricKey<*> = throw failure
        }
        shouldThrow<IllegalArgumentException> { invalid.toSymmetricKey() } shouldBe failure
        shouldThrow<IllegalArgumentException> { invalid.encrypt(plain) } shouldBe failure
        val sealed = specialized.first().encrypt(plain)
        shouldThrow<IllegalArgumentException> { sealed.decrypt(invalid) } shouldBe failure
        shouldThrow<IllegalArgumentException> { JsonWebKey().toSymmetricKey() }
        shouldThrow<IllegalArgumentException> { CoseKey(CoseKeyType.SYMMETRIC, keyParams = null).toSymmetricKey() }
    }

    "MAC typed equality and covariance retain the existing wire encoding" {
        val mac = CoseMacCreator(CoseAlgorithm.MAC.HS256, ByteArray(32)).mac0(
            CoseProtected(CoseAlgorithm.MAC.HS256), byteArrayOf(1, 2),
        )
        val bytes = coseCompliantSerializer.encodeToByteArray(mac)
        val decoded = CoseMac0<CoseProtected, EmptyCoseHeader, ByteArray>(bytes)
        decoded shouldBe mac
        decoded.hashCode() shouldBe mac.hashCode()
        val widened: CoseMac0<CoseHeader, CoseHeader, Any?> = decoded
        widened.payload shouldBe byteArrayOf(1, 2)
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe bytes
    }

    "generic COSE ES algorithms use the trusted key curve while ESP enforces its required curve" {
        val signer = ObservedSigner(Signer.Ephemeral { ec { curve = ECCurve.SECP_384_R_1; digest = Digest.SHA256 } })
        val signing = CoseSigner(signer)
        val signed = signing.sign1(CoseProtected(CoseAlgorithm.Signature.ES256), byteArrayOf(1))
        signer.makeVerifier().verify(signed.signatureInput(), signed.signature) shouldBe SignatureVerifier.Success
        val bytes = coseCompliantSerializer.encodeToByteArray(signed)
        val decoded = CoseSign1<CoseProtected, EmptyCoseHeader, ByteArray>(bytes)
        signer.makeVerifier().verify(decoded.signatureInput(), decoded.signature) shouldBe SignatureVerifier.Success
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe bytes
        shouldThrow<IllegalArgumentException> {
            signing.sign1(CoseProtected(CoseAlgorithm.Signature.ESP256), byteArrayOf(1))
        }
        signer.calls shouldBe 1
    }

    "both selectors reject an incompatible public key before signing" {
        val ec = Signer.Ephemeral { ec {} }
        val incompatible = ObservedSigner(object : Signer by ec {
            override val signatureAlgorithm = RsaAlgorithm.withSHA256andPSSPadding
        })
        shouldThrow<IllegalArgumentException> {
            JwsSigner(listOf(incompatible)).signCompact(JoseHeader(JwsAlgorithm.Signature.PS256), "payload")
        }
        shouldThrow<IllegalArgumentException> {
            CoseSigner(incompatible).sign1(CoseProtected(CoseAlgorithm.Signature.PS256), byteArrayOf(1))
        }
        incompatible.calls shouldBe 0
    }
}
