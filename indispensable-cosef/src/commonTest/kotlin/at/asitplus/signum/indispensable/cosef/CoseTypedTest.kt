package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/**
 * [CoseTyped]: typed builders, `typed()` decoding and [CoseTypedSerializerTemplate].
 */
@OptIn(ExperimentalSerializationApi::class)
val CoseTypedTest by matrixSuite {

    val payload = DataClass("alice")

    "sign1 wraps a typed payload in CBOR tag 24" {
        val typed = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = payload,
            payloadSerializer = DataClass.serializer(),
        ) { FAKE_SIGNATURE }

        typed.payload shouldBe payload
        typed.cose.plainPayload!!.hex() shouldStartWith "D818"
        typed.cose.plainPayload!!.hex() shouldBe encodePayload(payload, DataClass.serializer()).hex()
    }

    "sign1 signs over the encoded payload" {
        var signed: ByteArray? = null
        val typed = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = payload,
            payloadSerializer = DataClass.serializer(),
        ) {
            signed = it
            FAKE_SIGNATURE
        }

        signed!!.hex() shouldBe COSE.sign1StructureInput(
            plainProtectedHeader = RS256_HEADER_HEX.hexBytes(),
            payload = typed.cose.plainPayload!!,
        ).hex()
    }

    "sign1 passes a ByteArray payload through unchanged" {
        val typed = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = CONTENT,
            payloadSerializer = ByteArraySerializer(),
        ) { FAKE_SIGNATURE }

        typed.cose.plainPayload!!.hex() shouldBe CONTENT_HEX
        typed.payload.hex() shouldBe CONTENT_HEX
    }

    "sign1 rejects a ByteStringWrapper payload" {
        shouldThrow<IllegalArgumentException> {
            CoseTyped.sign1(
                protectedHeader = RS256_HEADER,
                payload = ByteStringWrapper("StringType"),
                payloadSerializer = ByteStringWrapper.serializer(String.serializer()),
            ) { FAKE_SIGNATURE }
        }
    }

    "typed() decodes the payload of a parsed CoseSign1" {
        val typed = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = payload,
            payloadSerializer = DataClass.serializer(),
        ) { FAKE_SIGNATURE }
        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), typed.cose))

        parsed.typed(DataClass.serializer()) shouldBe typed
        parsed.typed<DataClass>() shouldBe typed
    }

    "detached sign1 keeps the typed payload but leaves it out of the message" {
        var signed: ByteArray? = null
        val typed = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = payload,
            payloadSerializer = DataClass.serializer(),
            detached = true,
        ) {
            signed = it
            FAKE_SIGNATURE
        }

        typed.payload shouldBe payload
        typed.cose.plainPayload.shouldBeNull()
        typed.cose.signatureInput(
            detachedPayload = encodePayload(payload, DataClass.serializer())
        ).hex() shouldBe signed!!.hex()
    }

    "CoseTypedSerializerTemplate writes only the COSE object" {
        val typed = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = payload,
            payloadSerializer = DataClass.serializer(),
        ) { FAKE_SIGNATURE }
        val template = CoseTypedSerializerTemplate(CoseSign1.serializer(), DataClass.serializer())

        val cbor = coseCompliantSerializer.encodeToByteArray(template, typed)
        cbor.hex() shouldBe coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), typed.cose).hex()
        coseCompliantSerializer.decodeFromByteArray(template, cbor) shouldBe typed
    }

    "CoseTypedSerializerTemplate round-trips through JSON as a Base64 string" {
        val typed = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = payload,
            payloadSerializer = DataClass.serializer(),
        ) { FAKE_SIGNATURE }
        val template = CoseTypedSerializerTemplate(CoseSign1.serializer(), DataClass.serializer())

        val json = Json.encodeToString(template, typed)
        json shouldStartWith "\""
        json shouldBe Json.encodeToString(CoseSign1.serializer(), typed.cose)
        Json.decodeFromString(template, json) shouldBe typed
    }

    "CoseTypedSerializerTemplate cannot rebuild a detached payload" {
        // detached messages, such as ISO/IEC 18013-5 DeviceSignature, must be held as plain CoseSign1
        val detached = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = payload,
            payloadSerializer = DataClass.serializer(),
            detached = true,
        ) { FAKE_SIGNATURE }
        val template = CoseTypedSerializerTemplate(CoseSign1.serializer(), DataClass.serializer())
        val cbor = coseCompliantSerializer.encodeToByteArray(template, detached)

        shouldThrowAny { coseCompliantSerializer.decodeFromByteArray(template, cbor) }
    }

    "mac0 builds a typed CoseMac0" {
        var maced: ByteArray? = null
        val typed = CoseTyped.mac0(
            protectedHeader = HS256_HEADER,
            payload = payload,
            payloadSerializer = DataClass.serializer(),
        ) {
            maced = it
            FAKE_TAG
        }

        typed.payload shouldBe payload
        typed.cose.tag.hex() shouldBe FAKE_TAG.hex()
        typed.cose.macInput().hex() shouldBe maced!!.hex()

        val parsed = CoseMac0(coseCompliantSerializer.encodeToByteArray(CoseMac0.serializer(), typed.cose))
        parsed.typed(DataClass.serializer()) shouldBe typed
        parsed.typed<DataClass>() shouldBe typed

        val template = CoseTypedSerializerTemplate(CoseMac0.serializer(), DataClass.serializer())
        coseCompliantSerializer.decodeFromByteArray(
            template,
            coseCompliantSerializer.encodeToByteArray(template, typed)
        ) shouldBe typed
    }
}