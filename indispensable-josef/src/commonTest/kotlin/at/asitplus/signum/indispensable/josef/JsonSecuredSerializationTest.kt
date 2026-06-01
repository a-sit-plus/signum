package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestCompartment
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

val JsonSecuredSerializationTest by testSuite(compartment = { TestCompartment.Sequential }) {
    "JsonSecured serializer preserves concrete JWS forms" {
        val compactValue = JwsCompact(jwsCompactSerialization)
        val flattenedValue = jwsFlattenedSample()
        val generalValue = listOf(flattenedValue).toJwsGeneral()

        assertJsonSecuredRoundTrip(compactValue).shouldBeInstanceOf<JwsCompact>() shouldBe compactValue
        assertJsonSecuredRoundTrip(flattenedValue).shouldBeInstanceOf<JwsFlattened>() shouldBe flattenedValue
        assertJsonSecuredRoundTrip(generalValue).shouldBeInstanceOf<JwsGeneral>() shouldBe generalValue
    }

    "JsonSecured serializer preserves concrete JWE forms" {
        val flattenedValue = jweFlattenedSample()
        val compactValue = flattenedValue.toJweCompact()
        val generalValue = listOf(flattenedValue).toJweGeneral()

        assertJsonSecuredRoundTrip(compactValue).shouldBeInstanceOf<JweCompact>() shouldBe compactValue
        assertJsonSecuredRoundTrip(flattenedValue).shouldBeInstanceOf<JweFlattened>() shouldBe flattenedValue
        assertJsonSecuredRoundTrip(generalValue).shouldBeInstanceOf<JweGeneral>() shouldBe generalValue
    }

    "JsonSecured serializer rejects ambiguous and incomplete JOSE serializations" {
        val invalidCompactResult = runCatching {
            joseCompliantSerializer.decodeFromString<JsonSecured>(""" "a.b.c.d" """)
        }
        val ambiguousObjectResult = runCatching {
            joseCompliantSerializer.decodeFromString<JsonSecured>("""{"payload":"e30","ciphertext":"AQ"}""")
        }
        val incompleteObjectResult = runCatching {
            joseCompliantSerializer.decodeFromString<JsonSecured>("""{"protected":"eyJhbGciOiJSUzI1NiJ9"}""")
        }
        val arrayResult = runCatching {
            joseCompliantSerializer.decodeFromString<JsonSecured>("""[1,2,3]""")
        }
        val primitiveResult = runCatching {
            joseCompliantSerializer.decodeFromString<JsonSecured>("""1""")
        }

        invalidCompactResult.isSuccess shouldBe false
        invalidCompactResult.shouldBeFailure().message.shouldContain("expected 3 JWS parts or 5 JWE parts")

        ambiguousObjectResult.isSuccess shouldBe false
        ambiguousObjectResult.shouldBeFailure().message.shouldContain("must not contain both")

        incompleteObjectResult.isSuccess shouldBe false
        incompleteObjectResult.shouldBeFailure().message.shouldContain("must contain 'payload' or 'ciphertext'")

        arrayResult.isSuccess shouldBe false
        arrayResult.shouldBeFailure().message.shouldContain("expected a compact string or JSON object")

        primitiveResult.isSuccess shouldBe false
        primitiveResult.shouldBeFailure().message.shouldContain("expected a compact string or JSON object")
    }
}

private fun assertJsonSecuredRoundTrip(value: JsonSecured): JsonSecured {
    val serialized = joseCompliantSerializer.encodeToString(JsonSecured.serializer(), value)
    joseCompliantSerializer.decodeFromString<JsonElement>(serialized).shouldNotContainKey("type")
    return joseCompliantSerializer.decodeFromString<JsonSecured>(serialized)
}

private val jwsCompactSerialization = listOf(
    "eyJhbGciOiJSUzI1NiJ9",
    "e30",
    "AQID",
).joinToString(".")

private fun jwsFlattenedSample() = JwsFlattened(
    plainProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(
        JwsHeader.Part(algorithm = JwsAlgorithm.Signature.RS256)
    ),
    unprotectedHeader = null,
    plainPayload = "{}".encodeToByteArray(),
    plainSignature = byteArrayOf(1, 2, 3),
)

private fun jweFlattenedSample() = JweFlattened(
    plainProtectedHeader = JweProtectedHeaderSerializer.encodeToByteArray(
        JweHeader.Part(
            algorithm = JweAlgorithm.A128KW,
            encryption = JweEncryption.A128GCM,
        )
    ),
    sharedUnprotectedHeader = null,
    recipientUnprotectedHeader = null,
    encryptedKey = byteArrayOf(4, 5, 6),
    additionalAuthenticatedData = null,
    initializationVector = byteArrayOf(7, 8, 9, 10, 11, 12, 13, 14),
    ciphertext = byteArrayOf(15, 16, 17),
    authenticationTag = byteArrayOf(18, 19, 20),
)

private fun JsonElement.shouldNotContainKey(key: String) {
    when (this) {
        is JsonObject -> {
            (key in keys) shouldBe false
            values.forEach { it.shouldNotContainKey(key) }
        }

        is JsonArray -> forEach { it.shouldNotContainKey(key) }
        else -> Unit
    }
}
