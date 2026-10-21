package at.asitplus.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.CONTENT
import at.asitplus.signum.indispensable.cosef.COSE
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSign1
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.DataClass
import at.asitplus.signum.indispensable.cosef.CoseTyped
import at.asitplus.signum.indispensable.cosef.ES256_HEADER
import at.asitplus.signum.indispensable.cosef.EXTERNAL_AAD
import at.asitplus.signum.indispensable.cosef.hex
import at.asitplus.signum.indispensable.cosef.hexBytes
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.signature
import at.asitplus.signum.indispensable.cosef.typed
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.ByteArraySerializer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

val CoseJvmTest by matrixSuite {

    val keyPair: KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    fun sign(input: ByteArray): ByteArray = Signature.getInstance(ALGORITHM).run {
        initSign(keyPair.private)
        update(input)
        sign()
    }

    fun verify(input: ByteArray, signature: ByteArray): Boolean = Signature.getInstance(ALGORITHM).run {
        initVerify(keyPair.public)
        update(input)
        verify(signature)
    }

    /** Hand-built untagged COSE_Sign1 with an empty unprotected bucket. */
    fun foreignSign1(plainProtectedHeader: ByteArray, payload: ByteArray): ByteArray {
        val signature = sign(COSE.sign1StructureInput(plainProtectedHeader, payload = payload))
        return byteArrayOf(0x84.toByte()) +
                bstr(plainProtectedHeader) +
                byteArrayOf(0xA0.toByte()) +
                bstr(payload) +
                bstr(signature)
    }

    "CoseSign1 produces an ES256 signature that verifies" {
        val cose = CoseSign1(protectedHeader = ES256_HEADER, plainPayload = CONTENT) { sign(it) }
        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose))

        parsed.typed<ByteArray, CoseHeader>().signature.shouldBeInstanceOf<EcdsaSignature>()
        verify(parsed.signatureInput(), parsed.plainSignature).shouldBeTrue()
    }

    "legacy CoseSigned agrees for a canonically encoded protected header" {
        val cose = CoseSign1(
            protectedHeader = ES256_HEADER.copy(kid = "kid".encodeToByteArray()),
            plainPayload = CONTENT,
            externalAad = EXTERNAL_AAD,
        ) { sign(it) }
        val bytes = coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose)

        val legacy = CoseSigned.deserialize(ByteArraySerializer(), bytes).getOrThrow()
        legacy.prepareCoseSignatureInput(EXTERNAL_AAD).hex() shouldBe cose.signatureInput(EXTERNAL_AAD).hex()
        verify(legacy.prepareCoseSignatureInput(EXTERNAL_AAD), cose.plainSignature).shouldBeTrue()
    }

    "non-canonical protected header from a foreign issuer verifies with CoseSign1 only" {
        // {4: h'6B6964', 1: -7}: same content as CoseHeader(ES256, kid = "kid"), keys in the other order
        val plainProtectedHeader = "A204436B69640126".hexBytes()
        val wire = foreignSign1(plainProtectedHeader, CONTENT)

        val parsed = CoseSign1(wire)
        parsed.plainProtectedHeader.hex() shouldBe plainProtectedHeader.hex()
        verify(parsed.signatureInput(), parsed.plainSignature).shouldBeTrue()
        coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), parsed).hex() shouldBe wire.hex()

        val legacy = CoseSigned.deserialize(ByteArraySerializer(), wire).getOrThrow()
        legacy.protectedHeader shouldBe parsed.wrappedHeader<CoseHeader>().header
        legacy.prepareCoseSignatureInput().hex() shouldNotBe parsed.signatureInput().hex()
        verify(legacy.prepareCoseSignatureInput(), parsed.plainSignature).shouldBeFalse()
    }

    "protected header with an unknown label from a foreign issuer verifies with CoseSign1 only" {
        // {1: -7, 99: "x"}: label 99 is dropped on decode, so re-encoding loses it
        val plainProtectedHeader = "A2012618636178".hexBytes()
        val wire = foreignSign1(plainProtectedHeader, CONTENT)

        val parsed = CoseSign1(wire)
        parsed.protectedHeader.size shouldBe 2
        parsed.wrappedHeader<CoseHeader>().header shouldBe ES256_HEADER
        parsed.plainProtectedHeader.hex() shouldBe plainProtectedHeader.hex()
        verify(parsed.signatureInput(), parsed.plainSignature).shouldBeTrue()

        val legacy = CoseSigned.deserialize(ByteArraySerializer(), wire).getOrThrow()
        verify(legacy.prepareCoseSignatureInput(), parsed.plainSignature).shouldBeFalse()
    }

    "detached CoseSign1 verifies with the payload supplied separately" {
        val cose = CoseSign1(protectedHeader = ES256_HEADER, plainPayload = CONTENT, detached = true) { sign(it) }
        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose))

        verify(parsed.signatureInput(detachedPayload = CONTENT), parsed.plainSignature).shouldBeTrue()
        verify(
            parsed.signatureInput(detachedPayload = "other content".encodeToByteArray()),
            parsed.plainSignature
        ).shouldBeFalse()
    }

    "typed sign1 verifies over the tag-24 payload" {
        val typed = CoseTyped.sign1(
            protectedHeader = ES256_HEADER,
            payload = DataClass("alice"),
            payloadSerializer = DataClass.serializer(),
        ) { sign(it) }
        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), typed.cose))

        verify(parsed.signatureInput(), parsed.plainSignature).shouldBeTrue()
        parsed.typed(DataClass.serializer(), CoseHeader.serializer()) shouldBe typed
    }
}

private const val ALGORITHM = "SHA256withECDSAinP1363Format"

/** CBOR byte string header for lengths below 256. */
private fun bstr(bytes: ByteArray): ByteArray = when {
    bytes.size < 24 -> byteArrayOf((0x40 + bytes.size).toByte())
    bytes.size < 256 -> byteArrayOf(0x58, bytes.size.toByte())
    else -> error("not needed here")
} + bytes