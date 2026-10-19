@file:Suppress("DEPRECATION")

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.json.Json

/**
 * The new structure types against the deprecated [CoseSigned], [CoseMac] and [CoseInput]: for everything the old
 * model can represent, both must produce the same structures, the same wire bytes and the same JSON.
 *
 */
@OptIn(ExperimentalSerializationApi::class)
val CoseSignedRegressionTest by matrixSuite {

    val representableHeaders = listOf(
        CoseHeader(),
        ES256_HEADER,
        RS256_HEADER.copy(kid = "kid".encodeToByteArray()),
        RS256_HEADER.copy(contentType = "application/cbor"),
    )

    "sign1StructureInput matches the legacy Sig_structure" {
        for (header in representableHeaders) for (aad in listOf(byteArrayOf(), EXTERNAL_AAD)) {
            withClue("header=$header aad=${aad.hex()}") {
                val legacy = coseCompliantSerializer.encodeToByteArray(
                    CoseInput.serializer(),
                    CoseSigned.prepare(
                        protectedHeader = header,
                        externalAad = aad,
                        payload = CONTENT,
                        payloadSerializer = ByteArraySerializer(),
                    )
                )
                COSE.sign1StructureInput(COSE.encodeProtectedHeader(header), aad, CONTENT).hex() shouldBe legacy.hex()
            }
        }
    }

    "mac0StructureInput matches the legacy MAC_structure" {
        for (header in listOf(CoseHeader(), HS256_HEADER)) for (aad in listOf(byteArrayOf(), EXTERNAL_AAD)) {
            withClue("header=$header aad=${aad.hex()}") {
                val legacy = coseCompliantSerializer.encodeToByteArray(
                    CoseInput.serializer(),
                    CoseMac.prepare(
                        protectedHeader = header,
                        externalAad = aad,
                        payload = CONTENT,
                        payloadSerializer = ByteArraySerializer(),
                    )
                )
                COSE.mac0StructureInput(COSE.encodeProtectedHeader(header), aad, CONTENT).hex() shouldBe legacy.hex()
            }
        }
    }

    "CoseSign1 serializes byte-identically to legacy CoseSigned" {
        // a null unprotected bucket included: whatever it encodes to, it must not change
        for (unprotected in listOf(null, CoseHeader(kid = "kid".encodeToByteArray()))) {
            withClue("unprotected=$unprotected") {
                val legacy = CoseSigned.create(
                    protectedHeader = RS256_HEADER,
                    unprotectedHeader = unprotected,
                    payload = CONTENT,
                    signature = RsaSignature(FAKE_SIGNATURE),
                    payloadSerializer = ByteArraySerializer(),
                )
                val cose = CoseSign1(
                    protectedHeader = RS256_HEADER,
                    unprotectedHeader = unprotected,
                    plainPayload = CONTENT,
                ) { FAKE_SIGNATURE }

                coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose).hex() shouldBe
                        legacy.serialize(ByteArraySerializer()).hex()
                cose.signatureInput().hex() shouldBe legacy.prepareCoseSignatureInput().hex()
            }
        }
    }

    "detached CoseSign1 matches a legacy CoseSigned without payload" {
        val legacy = CoseSigned.create<ByteArray>(
            protectedHeader = RS256_HEADER,
            payload = null,
            signature = RsaSignature(FAKE_SIGNATURE),
            payloadSerializer = ByteArraySerializer(),
        )
        val cose = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT, detached = true) { FAKE_SIGNATURE }

        coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose).hex() shouldBe
                legacy.serialize(ByteArraySerializer()).hex()
        cose.signatureInput(detachedPayload = CONTENT).hex() shouldBe
                legacy.prepareCoseSignatureInput(detachedPayload = CONTENT).hex()
    }

    "CoseMac0 serializes byte-identically to legacy CoseMac" {
        for (unprotected in listOf(null, CoseHeader(kid = "kid".encodeToByteArray()))) {
            withClue("unprotected=$unprotected") {
                val legacy = CoseMac.create(
                    protectedHeader = HS256_HEADER,
                    unprotectedHeader = unprotected,
                    payload = CONTENT,
                    tag = FAKE_TAG,
                    payloadSerializer = ByteArraySerializer(),
                )
                val cose = CoseMac0(
                    protectedHeader = HS256_HEADER,
                    unprotectedHeader = unprotected,
                    plainPayload = CONTENT,
                ) { FAKE_TAG }

                coseCompliantSerializer.encodeToByteArray(CoseMac0.serializer(), cose).hex() shouldBe
                        legacy.serialize(ByteArraySerializer()).hex()
                cose.macInput().hex() shouldBe legacy.prepareCoseMacInput().hex()
            }
        }
    }

    "legacy CoseSigned bytes parse as CoseSign1 and back" {
        val legacy = CoseSigned.create(
            protectedHeader = RS256_HEADER,
            unprotectedHeader = CoseHeader(kid = "kid".encodeToByteArray()),
            payload = CONTENT,
            signature = RsaSignature(FAKE_SIGNATURE),
            payloadSerializer = ByteArraySerializer(),
        )
        val legacyBytes = legacy.serialize(ByteArraySerializer())

        val cose = CoseSign1(legacyBytes)
        cose.protectedHeader shouldBe legacy.protectedHeader
        cose.unprotectedHeader shouldBe legacy.unprotectedHeader
        cose.plainPayload!!.hex() shouldBe CONTENT_HEX
        cose.signature shouldBe legacy.signature
        cose.signatureInput().hex() shouldBe legacy.prepareCoseSignatureInput().hex()

        val coseBytes = coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose)
        CoseSigned.deserialize(ByteArraySerializer(), coseBytes).getOrThrow() shouldBe legacy
    }

    "legacy CoseMac bytes parse as CoseMac0 and back" {
        val legacy = CoseMac.create(
            protectedHeader = HS256_HEADER,
            payload = CONTENT,
            tag = FAKE_TAG,
            payloadSerializer = ByteArraySerializer(),
        )
        val legacyBytes = legacy.serialize(ByteArraySerializer())

        val cose = CoseMac0(legacyBytes)
        cose.protectedHeader shouldBe legacy.protectedHeader
        cose.tag.hex() shouldBe legacy.tag.hex()
        cose.macInput().hex() shouldBe legacy.prepareCoseMacInput().hex()

        val coseBytes = coseCompliantSerializer.encodeToByteArray(CoseMac0.serializer(), cose)
        CoseMac.deserialize(ByteArraySerializer(), coseBytes).getOrThrow() shouldBe legacy
    }

    "CoseSign1 JSON is interchangeable with legacy CoseSigned JSON" {
        val legacy = CoseSigned.create(
            protectedHeader = RS256_HEADER,
            payload = CONTENT,
            signature = RsaSignature(FAKE_SIGNATURE),
            payloadSerializer = ByteArraySerializer(),
        )
        val cose = CoseSign1(protectedHeader = RS256_HEADER, plainPayload = CONTENT) { FAKE_SIGNATURE }

        val legacyJson = Json.encodeToString(legacy)
        val coseJson = Json.encodeToString(CoseSign1.serializer(), cose)

        coseJson shouldBe legacyJson
        Json.decodeFromString(CoseSign1.serializer(), legacyJson) shouldBe cose
        Json.decodeFromString<CoseSigned<ByteArray>>(coseJson) shouldBe legacy
    }

    "CoseMac0 JSON is interchangeable with legacy CoseMac JSON" {
        val legacy = CoseMac.create(
            protectedHeader = HS256_HEADER,
            payload = CONTENT,
            tag = FAKE_TAG,
            payloadSerializer = ByteArraySerializer(),
        )
        val cose = CoseMac0(protectedHeader = HS256_HEADER, plainPayload = CONTENT) { FAKE_TAG }

        val legacyJson = Json.encodeToString(legacy)
        val coseJson = Json.encodeToString(CoseMac0.serializer(), cose)

        coseJson shouldBe legacyJson
        Json.decodeFromString(CoseMac0.serializer(), legacyJson) shouldBe cose
        Json.decodeFromString<CoseMac<ByteArray>>(coseJson) shouldBe legacy
    }

    "typed CoseSign1 matches legacy CoseSigned<P> on the wire and in JSON" {
        val payload = CoseTestPayload(name = "alice", count = 3)
        val legacy = CoseSigned.create(
            protectedHeader = RS256_HEADER,
            payload = payload,
            signature = RsaSignature(FAKE_SIGNATURE),
            payloadSerializer = CoseTestPayload.serializer(),
        )
        val typed = CoseTyped.sign1(
            protectedHeader = RS256_HEADER,
            payload = payload,
            payloadSerializer = CoseTestPayload.serializer(),
        ) { FAKE_SIGNATURE }
        val template = CoseTypedSerializerTemplate(CoseSign1.serializer(), CoseTestPayload.serializer())

        typed.cose.plainPayload!!.hex() shouldBe legacy.wireFormat.payload!!.hex()
        typed.cose.signatureInput().hex() shouldBe legacy.prepareCoseSignatureInput().hex()

        val legacyJson = Json.encodeToString(legacy)
        Json.encodeToString(template, typed) shouldBe legacyJson
        Json.decodeFromString(template, legacyJson) shouldBe typed
        Json.decodeFromString<CoseSigned<CoseTestPayload>>(Json.encodeToString(template, typed)).payload shouldBe payload
    }

    "typed payload decoding agrees with legacy CoseSigned<P>" {
        val payload = CoseTestPayload(name = "bob", count = 7)
        val legacy = CoseSigned.create(
            protectedHeader = RS256_HEADER,
            payload = payload,
            signature = RsaSignature(FAKE_SIGNATURE),
            payloadSerializer = CoseTestPayload.serializer(),
        )

        CoseSign1(legacy.serialize(CoseTestPayload.serializer()))
            .typed(CoseTestPayload.serializer()).payload shouldBe legacy.payload
    }
}