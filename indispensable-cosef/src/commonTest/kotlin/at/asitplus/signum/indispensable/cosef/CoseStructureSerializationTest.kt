package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldEndWith
import io.kotest.matchers.string.shouldStartWith
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.CborInteger

/**
 * RFC 9052 structure building, protected-header handling, and the wire forms of [CoseSign1] and [CoseMac0].
 *
 */
@OptIn(ExperimentalSerializationApi::class)
val CoseStructureSerializationTest by matrixSuite {

    "sign1StructureInput matches the RFC 9052 example" {
        COSE.sign1StructureInput(
            plainProtectedHeader = ES256_HEADER_HEX.hexBytes(),
            payload = CONTENT,
        ).hex() shouldBe "846A5369676E61747572653143A10126" + "40" + "54" + CONTENT_HEX
    }

    "mac0StructureInput uses the MAC0 context" {
        COSE.mac0StructureInput(
            plainProtectedHeader = HS256_HEADER_HEX.hexBytes(),
            payload = CONTENT,
        ).hex() shouldBe "84644D41433043A10105" + "40" + "54" + CONTENT_HEX
    }

    "structure inputs encode an empty protected header and the external AAD as byte strings" {
        COSE.sign1StructureInput(
            plainProtectedHeader = byteArrayOf(),
            externalAad = EXTERNAL_AAD,
            payload = CONTENT,
        ).hex() shouldBe "846A5369676E617475726531" + "40" + "4C11AA22BB33CC44DD55006699" + "54" + CONTENT_HEX
    }

    "an empty protected header is transmitted as a zero-length byte string" {
        CoseSign1(protectedHeader = CoseHeader(), plainPayload = CONTENT) { FAKE_SIGNATURE }
            .plainProtectedHeader.size shouldBe 0
        CoseSign1(protectedHeader = ES256_HEADER, plainPayload = CONTENT) { FAKE_SIGNATURE }
            .plainProtectedHeader.hex() shouldBe ES256_HEADER_HEX
    }

    "both empty forms of the protected header are accepted (RFC 9052 section 3)" {
        for (protected in listOf("40", "41A0")) {
            val parsed = CoseSign1(("84" + protected + "A0" + "54" + CONTENT_HEX + "43" + FAKE_SIGNATURE.hex()).hexBytes())
            parsed.protectedHeader.isEmpty().shouldBeTrue()
            parsed.wrappedHeader<CoseHeader>().header shouldBe CoseHeader()
        }
    }

    // ---- CoseSign1 --------------------------------------------------------------------------------------------

    "CoseSign1 signs the Sig_structure over the encoded protected header" {
        var signed: ByteArray? = null
        val cose = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT) { input ->
            signed = input
            FAKE_SIGNATURE
        }

        signed!!.hex() shouldBe COSE.sign1StructureInput(RS256_HEADER_HEX.hexBytes(), payload = CONTENT).hex()
        cose.signatureInput().hex() shouldBe signed.hex()
        cose.plainProtectedHeader.hex() shouldBe RS256_HEADER_HEX
        cose.protectedHeader[1] shouldBe CborInteger(-257)
        cose.wrappedHeader<CoseHeader>().header shouldBe RS256_HEADER
        cose.plainPayload!!.hex() shouldBe CONTENT_HEX
        cose.typed<ByteArray, CoseHeader>().signature shouldBe RsaSignature(FAKE_SIGNATURE)
    }

    "CoseSign1 round-trips through CBOR" {
        val cose = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT) { FAKE_SIGNATURE }
        val bytes = coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose)

        bytes.hex() shouldStartWith "8445" + RS256_HEADER_HEX
        bytes.hex() shouldEndWith "43" + FAKE_SIGNATURE.hex()

        val parsed = CoseSign1(bytes)
        parsed shouldBe cose
        coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), parsed).hex() shouldBe bytes.hex()
    }

    "CoseSign1 includes the external AAD in the signature input" {
        var signed: ByteArray? = null
        val cose = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT, externalAad = EXTERNAL_AAD) {
            signed = it
            FAKE_SIGNATURE
        }

        cose.signatureInput(externalAad = EXTERNAL_AAD).hex() shouldBe signed!!.hex()
        cose.signatureInput().hex() shouldNotBe signed.hex()
    }

    "detached CoseSign1 signs the payload but leaves it out of the message" {
        var signed: ByteArray? = null
        val cose = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT, detached = true) {
            signed = it
            FAKE_SIGNATURE
        }

        cose.plainPayload.shouldBeNull()
        cose.signatureInput(detachedPayload = CONTENT).hex() shouldBe signed!!.hex()
        shouldThrow<IllegalArgumentException> { cose.signatureInput() }
        cose.getPayload(ByteArraySerializer()).isFailure.shouldBeTrue()

        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose))
        parsed shouldBe cose
        parsed.plainPayload.shouldBeNull()
    }

    "attached CoseSign1 rejects a detached payload" {
        val cose = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT) { FAKE_SIGNATURE }
        shouldThrow<IllegalArgumentException> { cose.signatureInput(detachedPayload = CONTENT) }
    }

    "CoseSign1 parsing rejects malformed input with a SerializationException" {
        shouldThrow<SerializationException> { CoseSign1(byteArrayOf(0x01, 0x02)) }
    }

    "CoseSign1 equality is by content" {
        val cose = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT) { FAKE_SIGNATURE }
        val bytes = coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose)
        val first = CoseSign1(bytes)
        val second = CoseSign1(bytes)

        first shouldBe second
        first.hashCode() shouldBe second.hashCode()

        val other = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT) { "baz".encodeToByteArray() }
        other shouldNotBe cose
    }

    "CoseSign1 inside a serializable class round-trips through CBOR" {
        val holder = CoseSign1Holder(
            CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT) { FAKE_SIGNATURE }
        )

        val cbor = coseCompliantSerializer.encodeToByteArray(CoseSign1Holder.serializer(), holder)
        coseCompliantSerializer.decodeFromByteArray(CoseSign1Holder.serializer(), cbor) shouldBe holder
    }

    "CoseSign1 rejects a header parameter in both buckets" {
        val wire = ("84" + "45" + RS256_HEADER_HEX + RS256_HEADER_HEX + "54" + CONTENT_HEX + "43" + FAKE_SIGNATURE.hex())
            .hexBytes()
        shouldThrow<SerializationException> { CoseSign1(wire) }
        shouldThrow<IllegalArgumentException> {
            CoseSign1(protectedHeader = RS256_HEADER, unprotectedHeader = RS256_HEADER, plainPayload = CONTENT) {
                FAKE_SIGNATURE
            }
        }
    }

    // ---- CoseMac0 ---------------------------------------------------------------------------------------------

    "CoseMac0 MACs the MAC_structure over the encoded protected header" {
        var maced: ByteArray? = null
        val cose = CoseMac0(protectedHeader = HS256_HEADER, plainPayload = CONTENT) { input ->
            maced = input
            FAKE_TAG
        }

        maced!!.hex() shouldBe COSE.mac0StructureInput(HS256_HEADER_HEX.hexBytes(), payload = CONTENT).hex()
        cose.macInput().hex() shouldBe maced.hex()
        cose.wrappedHeader<CoseHeader>().header shouldBe HS256_HEADER
        cose.protectedHeader shouldBe HS256_HEADER.toBucket()
        cose.tag.hex() shouldBe FAKE_TAG.hex()
    }

    "CoseMac0 round-trips through CBOR" {
        val cose = CoseMac0(protectedHeader = HS256_HEADER, plainPayload = CONTENT) { FAKE_TAG }

        val bytes = coseCompliantSerializer.encodeToByteArray(CoseMac0.serializer(), cose)
        bytes.hex() shouldStartWith "8443" + HS256_HEADER_HEX
        CoseMac0(bytes) shouldBe cose
    }

    "detached CoseMac0 authenticates the payload but leaves it out of the message" {
        var maced: ByteArray? = null
        val cose = CoseMac0(protectedHeader = HS256_HEADER, plainPayload = CONTENT, detached = true) {
            maced = it
            FAKE_TAG
        }

        cose.plainPayload.shouldBeNull()
        cose.macInput(detachedPayload = CONTENT).hex() shouldBe maced!!.hex()
        shouldThrow<IllegalArgumentException> { cose.macInput() }
    }

    "CoseMac0 parsing rejects malformed input with a SerializationException" {
        shouldThrow<SerializationException> { CoseMac0(byteArrayOf(0x01, 0x02)) }
    }

    "CoseMac0 rejects a header parameter in both buckets" {
        val wire = ("84" + "43" + HS256_HEADER_HEX + HS256_HEADER_HEX + "54" + CONTENT_HEX + "43" + FAKE_TAG.hex())
            .hexBytes()
        shouldThrow<SerializationException> { CoseMac0(wire) }
    }
}

@Serializable
private data class CoseSign1Holder(val cose: CoseSign1)