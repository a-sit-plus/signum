@file:Suppress("DEPRECATION")

package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldEndWith
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

val JwsSignedRegressionTest by testSuite {
    "JwsCompact.invoke signs the protected-header bytes derived from JwsHeader.toPart" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-1",
        )
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        var capturedAlgorithm: JwsAlgorithm? = null
        var capturedInput: ByteArray? = null

        val compact = JwsCompact.invoke(
            protectedHeader = header,
            payload = payload,
        ) { algorithm, signingInput ->
            capturedAlgorithm = algorithm
            capturedInput = signingInput
            byteArrayOf(1, 2, 3, 4)
        }

        val expectedProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(header.toPart())

        capturedAlgorithm shouldBe header.algorithm
        compact.plainProtectedHeader shouldBe expectedProtectedHeader
        capturedInput shouldBe JWS.getSignatureInput(expectedProtectedHeader, payload)
        compact.signatureInput shouldBe capturedInput
    }

    "legacy compact serialization matches JwsCompact for RS256" {
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "JWT",
                keyId = "kid-rs256",
            ),
            payload = """{"iss":"https://issuer.example","aud":"example"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(5, 4, 3, 2, 1),
        )

        regressionCase.legacy.header shouldBe regressionCase.compact.jwsHeader
        regressionCase.legacy.signature shouldBe regressionCase.compact.signature
        regressionCase.legacy.plainSignatureInput shouldBe regressionCase.compact.signatureInput

        val compactJson = joseCompliantSerializer.encodeToString(JwsCompact.serializer(), regressionCase.compact)

        compactJson.removeSurrounding("\"") shouldBe regressionCase.legacy.serialize()
        joseCompliantSerializer.decodeFromString(JwsCompact.serializer(), compactJson) shouldBe regressionCase.compact
        JwsSigned.deserialize(regressionCase.legacy.serialize()).getOrThrow() shouldBe regressionCase.legacy
    }

    "typed payload decoding matches between JwsSigned and JwsCompact" {
        val typedPayload = JsonObject(
            mapOf(
                "iss" to JsonPrimitive("https://issuer.example"),
                "sub" to JsonPrimitive("alice"),
                "admin" to JsonPrimitive(true),
            )
        )
        val payload = joseCompliantSerializer.encodeToString(JsonObject.serializer(), typedPayload).encodeToByteArray()
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeader.Part(
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

        legacyTyped.header shouldBe regressionCase.compact.jwsHeader
        legacyTyped.payload shouldBe regressionCase.compact.getPayload(JsonObject.serializer())
        legacyTyped.signature shouldBe regressionCase.compact.signature
        legacyTyped.plainSignatureInput shouldBe regressionCase.compact.signatureInput
    }

    "single-signature conversion path preserves the JwsSigned view" {
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-general",
            ),
            payload = """{"nonce":"1234"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(0x2a),
        )

        val flattened = regressionCase.compact.toJwsFlattened()
        val general = listOf(flattened).toJwsGeneral()

        flattened.jwsHeader shouldBe regressionCase.legacy.header
        flattened.signature shouldBe regressionCase.legacy.signature
        flattened.signatureInput shouldBe regressionCase.legacy.plainSignatureInput

        general.jwsHeaders[0] shouldBe regressionCase.legacy.header
        general.signatures[0] shouldBe regressionCase.legacy.signature
        general.signatureInputs[0] shouldBe regressionCase.legacy.plainSignatureInput
    }

    "empty payload keeps the compact separator for both APIs" {
        val regressionCase = compactRegressionCase(
            protectedHeader = JwsHeader.Part(
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
            protectedHeader = JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.ES256,
                type = "application/example+jws",
            ),
            payload = """{"sub":"alice"}""".encodeToByteArray(),
            plainSignature = plainSignature,
        )

        val legacy = JwsSigned.deserialize(regressionCase.legacy.serialize()).getOrThrow()

        legacy.header.algorithm shouldBe JwsAlgorithm.Signature.ES256
        legacy.signature shouldBe regressionCase.compact.signature
        legacy.signature.rawByteArray shouldBe plainSignature
        legacy.signature.shouldBeInstanceOf<CryptoSignature.EC.DefiniteLength>()
        regressionCase.compact.signature.shouldBeInstanceOf<CryptoSignature.EC.DefiniteLength>()
    }
}

private data class CompactRegressionCase(
    val legacy: JwsSigned<ByteArray>,
    val compact: JwsCompact,
)

private fun compactRegressionCase(
    protectedHeader: JwsHeader.Part,
    payload: ByteArray,
    plainSignature: ByteArray,
): CompactRegressionCase {
    val header = JwsHeader.fromParts(protectedHeader, null)
    val compact = JwsCompact(
        plainProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(protectedHeader),
        payload = payload,
        plainSignature = plainSignature,
    )

    return CompactRegressionCase(
        legacy = JwsSigned(
            header = header,
            payload = payload,
            signature = JWS.getSignature(header.algorithm, plainSignature),
            plainSignatureInput = JwsSigned.prepareJwsSignatureInput(header, payload),
        ),
        compact = compact,
    )
}
