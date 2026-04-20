package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.*

val UnknownKeyWrapperTest by testSuite {
    "generic wrapper serializer preserves unknown JWT claims" {
        val serializer = JsonWebTokenAllKeysSerializer
        val json = """
            {
              "iss": "issuer",
              "sub": "subject",
              "custom_string": "custom",
              "custom_object": { "flag": true }
            }
        """.trimIndent()

        val decoded = joseCompliantSerializer.decodeFromString(serializer, json)

        decoded shouldBe JsonWebTokenAllKeys(
            baseStructure = JsonWebToken(
                issuer = "issuer",
                subject = "subject",
            ),
            unknownKeys = mapOf(
                "custom_string" to JsonPrimitive("custom"),
                "custom_object" to buildJsonObject {
                    put("flag", true)
                },
            ),
        )

        val encoded = joseCompliantSerializer.encodeToJsonElement(serializer, decoded)

        joseCompliantSerializer.decodeFromJsonElement<JsonWebToken>(encoded) shouldBe decoded.baseStructure
        encoded shouldBe joseCompliantSerializer.encodeToJsonElement(
            mapOf(
                "iss" to JsonPrimitive("issuer"),
                "sub" to JsonPrimitive("subject"),
                "custom_string" to JsonPrimitive("custom"),
                "custom_object" to buildJsonObject {
                    put("flag", true)
                },
            ),
        )
    }

    "JwsHeaderAllKeys serializes with the concrete wrapper serializer" {
        val json = """{"alg":"ES256","kid":"did:example:signer","private_claim":"value"}"""

        val decoded = joseCompliantSerializer.decodeFromString(JwsHeaderAllKeys.serializer(), json)

        decoded shouldBe JwsHeaderAllKeys(
            baseStructure = JwsHeader(
                algorithm = JwsAlgorithm.Signature.ES256,
                keyId = "did:example:signer",
            ),
            unknownKeys = mapOf("private_claim" to JsonPrimitive("value")),
        )
    }

    "encoding rejects unknown keys that collide with known JOSE names" {
        val serializer = JwsHeaderAllKeysSerializer

        runCatching {
            joseCompliantSerializer.encodeToJsonElement(
                serializer,
                JwsHeaderAllKeys(
                    baseStructure = JwsHeader(
                        algorithm = JwsAlgorithm.Signature.ES256,
                    ),
                    unknownKeys = mapOf("alg" to JsonPrimitive("HS256")),
                ),
            )
        }.shouldBeFailure().message shouldBe "Encoding failed"
    }
}
