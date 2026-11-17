package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonArray

val JwsHeaderWrappedTest by matrixSuite {
    "custom headers split and decode with explicit and reified serializers" {
        val header = SigningHeader(JwsAlgorithm.Signature.RS256, "custom-key", "custom-value")
        val explicit = JwsHeaderWrapped(header, SigningHeader.serializer(), setOf("extension"))
        val reified = JwsHeaderWrapped(header, setOf("extension"))

        explicit shouldBe reified
        explicit.protectedHeader.toProtectedHeaderJsonObject() shouldBe JsonObject(
            mapOf("alg" to JsonPrimitive("RS256"), "kid" to JsonPrimitive("custom-key"))
        )
        explicit.unprotectedHeader shouldBe JsonObject(mapOf("extension" to JsonPrimitive("custom-value")))
        JwsHeaderWrapped.fromParts(
            SigningHeader.serializer(), explicit.protectedHeader, explicit.unprotectedHeader
        ) shouldBe explicit
        JwsHeaderWrapped.fromJsonObjects<SigningHeader>(
            explicit.protectedHeader.toProtectedHeaderJsonObject(), explicit.unprotectedHeader
        ) shouldBe explicit
    }

    "equality ignores unprotected member set order" {
        val header = SigningHeader(JwsAlgorithm.Signature.RS256, "key", "value")
        val first = JwsHeaderWrapped(header, linkedSetOf("kid", "extension"))
        val second = JwsHeaderWrapped(header, linkedSetOf("extension", "kid"))

        first.unprotectedHeaderMembers shouldBe setOf("kid", "extension")
        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
        (first == JwsHeaderWrapped(header)) shouldBe false
    }

    "cached fragments remain available with an erased header type" {
        var encodings = 0
        val serializer = object : KSerializer<SigningHeader> by SigningHeader.serializer() {
            override fun serialize(encoder: Encoder, value: SigningHeader) {
                encodings++
                SigningHeader.serializer().serialize(encoder, value)
            }
        }
        val placement = mutableSetOf("extension")
        val wrapped: JwsHeaderWrapped<*> = JwsHeaderWrapped(
            SigningHeader(JwsAlgorithm.Signature.RS256, extension = "value"), serializer, placement,
        )
        placement.clear()

        repeat(2) {
            wrapped.protectedHeader.toProtectedHeaderJsonObject() shouldBe
                    JsonObject(mapOf("alg" to JsonPrimitive("RS256")))
            wrapped.unprotectedHeader shouldBe JsonObject(mapOf("extension" to JsonPrimitive("value")))
        }
        wrapped.unprotectedHeaderMembers shouldBe setOf("extension")
        encodings shouldBe 1
    }

    "factories cache fragments using the supplied JSON configuration" {
        val format = Json(joseCompliantSerializer) { encodeDefaults = true }
        val wrapped = JwsHeaderWrapped(
            SigningHeader(JwsAlgorithm.Signature.RS256, extension = "value", crit = listOf("extension")), setOf("kid"), serialFormat = format,
        )

        wrapped.unprotectedHeader shouldBe JsonObject(mapOf("kid" to JsonNull))
        wrapped.unprotectedHeaderMembers shouldBe setOf("kid")
        val decoded = JwsHeaderWrapped.fromParts<SigningHeader>(
            wrapped.protectedHeader, wrapped.unprotectedHeader, format,
        )
        decoded.protectedHeader shouldBe wrapped.protectedHeader
        decoded.unprotectedHeader shouldBe wrapped.unprotectedHeader
    }

    "duplicate extension names are rejected before header decoding" {
        val result = runCatching {
            JwsHeaderWrapped.fromJsonObjects<SigningHeader>(
                JsonObject(mapOf("alg" to JsonPrimitive("RS256"), "extension" to JsonPrimitive("a"))),
                JsonObject(mapOf("extension" to JsonPrimitive("b"))),
            )
        }
        result.shouldBeFailure().shouldBeInstanceOf<IllegalArgumentException>()
            .message.shouldContain("Duplicate keys: extension")
    }

    "critical parameters are protected nonempty unique names referencing protected members" {
        val base = mapOf("alg" to JsonPrimitive("RS256"), "extension" to JsonPrimitive("value"))
        for (crit in listOf(
            JsonArray(emptyList()), JsonNull, JsonPrimitive("extension"),
            JsonArray(listOf(JsonPrimitive(1))),
            JsonArray(listOf(JsonPrimitive("extension"), JsonPrimitive("extension"))),
            JsonArray(listOf(JsonPrimitive("missing"))),
            JsonArray(listOf(JsonPrimitive("crit"))),
        )) {
            shouldThrow<IllegalArgumentException> {
                JwsHeaderWrapped.fromJsonObjects<SigningHeader>(JsonObject(base + ("crit" to crit)))
            }
        }
        val critical = JsonArray(listOf(JsonPrimitive("extension")))
        shouldThrow<IllegalArgumentException> {
            JwsHeaderWrapped.fromJsonObjects<SigningHeader>(JsonObject(base), JsonObject(mapOf("crit" to critical)))
        }
        shouldThrow<IllegalArgumentException> {
            JwsHeaderWrapped.fromJsonObjects<SigningHeader>(
                JsonObject(mapOf("alg" to JsonPrimitive("RS256"), "crit" to critical)),
                JsonObject(mapOf("extension" to JsonPrimitive("value"))),
            )
        }
        JwsHeaderWrapped.fromJsonObjects<SigningHeader>(JsonObject(base + ("crit" to critical))).header.crit shouldBe listOf("extension")
    }

    "received critical references may name unmodeled protected extensions" {
        val protected = """{"alg":"RS256","vendor":1,"crit":["vendor"]}""".encodeToByteArray()
        val raw = JwsFlattened.Raw(protected, null, "{}".encodeToByteArray(), byteArrayOf(1))
        val typed = raw.typed<SigningHeader, SigningPayload>()
        typed.header.crit shouldBe listOf("vendor")
        typed.raw.plainProtectedHeader shouldBe protected
        typed.raw shouldBe raw
    }
}
