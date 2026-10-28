@file:Suppress("DEPRECATION")

package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldEndWith
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

val JwsRawSignedRegressionTest by matrixSuite {
    "legacy compact serialization matches JwsCompact.Raw for RS256" {
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "JWT",
                keyId = "kid-rs256",
            ),
            payload = """{"iss":"https://issuer.example","aud":"example"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(5, 4, 3, 2, 1),
        )
        val typedCompact = regressionCase.compact.typed<JsonObject, JwsHeaderMonolith>()

        regressionCase.legacy.header shouldBe typedCompact.wrappedHeader.header
        regressionCase.legacy.signature shouldBe typedCompact.signature
        regressionCase.legacy.plainSignatureInput shouldBe regressionCase.compact.signatureInput

        val compactJson = joseCompliantSerializer.encodeToString(JwsCompactRawStringSerializer, regressionCase.compact)

        compactJson.removeSurrounding("\"") shouldBe regressionCase.legacy.serialize()
        joseCompliantSerializer.decodeFromString(
            JwsCompactRawStringSerializer,
            compactJson
        ) shouldBe regressionCase.compact
        JwsSigned.deserialize(regressionCase.legacy.serialize()).getOrThrow() shouldBe regressionCase.legacy
    }

    "JwsCompact.Raw.parse decodes compact serialization and typed payload" {
        val typedPayload = JsonObject(
            mapOf(
                "iss" to JsonPrimitive("https://issuer.example"),
                "sub" to JsonPrimitive("alice"),
            )
        )
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "JWT",
            ),
            payload = joseCompliantSerializer.encodeToString(JsonObject.serializer(), typedPayload).encodeToByteArray(),
            plainSignature = byteArrayOf(1, 2, 3, 4),
        )

        val (parsedCompact, parsedPayload, parsedHeader) = JwsCompact.Raw.parse<JsonObject, JwsHeaderMonolith>(
            base64UrlString = regressionCase.compact.toString(),
            serialFormat = joseCompliantSerializer,
        ).getOrThrow()

        parsedCompact shouldBe regressionCase.compact
        parsedHeader shouldBe regressionCase.compact.typed<JsonObject, JwsHeaderMonolith>().wrappedHeader
        parsedPayload shouldBe typedPayload
    }

    "typed payload decoding matches between JwsSigned and JwsCompact.Raw" {
        val typedPayload = JsonObject(
            mapOf(
                "iss" to JsonPrimitive("https://issuer.example"),
                "sub" to JsonPrimitive("alice"),
                "admin" to JsonPrimitive(true),
            )
        )
        val payload = joseCompliantSerializer.encodeToString(JsonObject.serializer(), typedPayload).encodeToByteArray()
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jwt",
            ),
            payload = payload,
            plainSignature = byteArrayOf(9, 8, 7, 6),
        )

        val legacyTyped = JwsSigned.deserialize(
            deserializationStrategy = JsonObject.serializer(),
            it = regressionCase.legacy.serialize(),
            json = joseCompliantSerializer,
        ).getOrThrow()
        val typedCompact = regressionCase.compact.typed<JsonObject, JwsHeaderMonolith>()

        legacyTyped.header shouldBe typedCompact.wrappedHeader.header
        legacyTyped.payload shouldBe regressionCase.compact.getPayload(JsonObject.serializer()).getOrThrow()
        legacyTyped.signature shouldBe typedCompact.signature
        legacyTyped.plainSignatureInput shouldBe regressionCase.compact.signatureInput
    }

    "single-signature conversion path preserves the JwsSigned view" {
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-general",
            ),
            payload = """{"nonce":"1234"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(0x2a),
        )

        val flattened = regressionCase.compact.toFlattened()
        val general = listOf(flattened).toGeneral()
        val typedFlattened = flattened.typed<JsonObject, JwsHeaderMonolith>()
        val typedGeneral = general.typed<JsonObject, JwsHeaderMonolith>()

        typedFlattened.wrappedHeader.header shouldBe regressionCase.legacy.header
        typedFlattened.wrappedHeader.unprotectedHeaderMembers shouldBe emptySet()
        typedFlattened.signature shouldBe regressionCase.legacy.signature
        flattened.signatureInput shouldBe regressionCase.legacy.plainSignatureInput

        typedGeneral.wrappedHeaders[0].header shouldBe regressionCase.legacy.header
        typedGeneral.wrappedHeaders[0].unprotectedHeaderMembers shouldBe emptySet()
        typedGeneral.signatures[0] shouldBe regressionCase.legacy.signature
        general.signatureInputs[0] shouldBe regressionCase.legacy.plainSignatureInput
    }

    "empty payload keeps the compact separator for both APIs" {
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
            ),
            payload = byteArrayOf(),
            plainSignature = byteArrayOf(1),
        )

        regressionCase.legacy.plainSignatureInput.decodeToString().shouldEndWith(".")
        regressionCase.compact.signatureInput.decodeToString().shouldEndWith(".")
        regressionCase.legacy.serialize() shouldBe regressionCase.compact.toString()

        JwsSigned.deserialize(regressionCase.legacy.serialize()).getOrThrow().payload shouldBe byteArrayOf()
    }

    "ES256 compact signatures are decoded as EC signatures in both APIs" {
        val plainSignature = ByteArray(64) { (it + 1).toByte() }
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.ES256,
                type = "application/example+jws",
            ),
            payload = """{"sub":"alice"}""".encodeToByteArray(),
            plainSignature = plainSignature,
        )

        val legacy = JwsSigned.deserialize(regressionCase.legacy.serialize()).getOrThrow()
        val typedCompact = regressionCase.compact.typed<JsonObject, JwsHeaderMonolith>()

        legacy.header.algorithm shouldBe JwsAlgorithm.Signature.ES256
        legacy.signature shouldBe typedCompact.signature
        legacy.signature.joseBytes shouldBe plainSignature
        legacy.signature.shouldBeInstanceOf<EcdsaSignature.DefiniteLength>()
        typedCompact.signature.shouldBeInstanceOf<EcdsaSignature.DefiniteLength>()
    }
}

private data class CompactRegressionCase(
    val legacy: JwsSigned<ByteArray>,
    val compact: JwsCompact.Raw,
)

private fun compactRegressionCase(
    protectedHeader: JwsHeaderMonolith,
    payload: ByteArray,
    plainSignature: ByteArray,
): CompactRegressionCase {
    val header = protectedHeader
    val compact = JwsCompact.Raw(
        plainProtectedHeader = JwsHeaderWrapped(protectedHeader).protectedHeader,
        plainPayload = payload,
        plainSignature = plainSignature,
    )

    return CompactRegressionCase(
        legacy = JwsSigned(
            header = header,
            payload = payload,
            signature = JwsRaw.getSignature(header.algorithm, plainSignature),
            plainSignatureInput = JwsSigned.prepareJwsSignatureInput(header, payload),
        ),
        compact = compact,
    )
}
