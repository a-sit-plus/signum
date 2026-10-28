package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.jsonObject

val JwsCustomHeaderTest by matrixSuite {
    "custom typed views preserve the exact compact bytes through conversions and serialization" {
        val protectedBytes = """{ "extension": "private", "kid": "custom-key", "alg": "RS256" }"""
            .encodeToByteArray()
        val payloadBytes = """{ "sub": "alice" }""".encodeToByteArray()
        val compact = JwsCompact.Raw(protectedBytes, payloadBytes, byteArrayOf(1, 2, 3))
        val typed = compact.typed<CustomJwsHeader, JsonObject>()

        (typed.jws === compact) shouldBe true
        typed.wrappedHeader.header.extension shouldBe "private"
        typed.signature.joseBytes shouldBe compact.plainSignature
        val converted = typed.toFlattened().toCompact()
        converted shouldBe typed
        converted.jws.plainProtectedHeader shouldBe protectedBytes
        converted.jws.plainPayload shouldBe payloadBytes
        converted.jws.signatureInput shouldBe compact.signatureInput

        val serializer = JwsTypedSerializerTemplate(
            JwsCompactRawStringSerializer, JsonObject.serializer(), CustomJwsHeader.serializer()
        )
        val encoded = joseCompliantSerializer.encodeToString(serializer, typed)
        encoded shouldBe joseCompliantSerializer.encodeToString(JwsCompactRawStringSerializer, compact)
        val decoded = joseCompliantSerializer.decodeFromString(serializer, encoded)
        decoded shouldBe typed
        JwsCompact.Raw.parse<CustomJwsHeader, JsonObject>(compact.toString()).getOrThrow().third shouldBe typed.wrappedHeader
        JwsCompact<CustomJwsHeader, JsonObject>(compact.toString()) shouldBe typed
    }

    "custom headers retain placement and signature order in flattened and general typed views" {
        val payload = JsonObject(mapOf("sub" to JsonPrimitive("alice")))
        val bytes = joseCompliantSerializer.encodeToString(JsonObject.serializer(), payload).encodeToByteArray()
        val headers = listOf(
            JwsHeaderWrapped(CustomJwsHeader(JwsAlgorithm.Signature.RS256, "first", "one"), setOf("extension")),
            JwsHeaderWrapped(CustomJwsHeader(JwsAlgorithm.Signature.RS256, "second", "two"), setOf("kid")),
        )
        val signatures = listOf(byteArrayOf(1, 2), byteArrayOf(3, 4))
        val flattened = headers.mapIndexed { index, header ->
            flattenedSample(header, bytes, signatures[index]).typed<CustomJwsHeader, JsonObject>()
        }
        val general = flattened.map { it.jws }.toGeneral().typed<CustomJwsHeader, JsonObject>()

        general.payload shouldBe payload
        general.wrappedHeaders shouldBe headers
        general.signatures.map { it.joseBytes } shouldBe signatures
        general.toFlattened() shouldBe flattened
        general.jws.signatureInputs shouldBe flattened.map { it.jws.signatureInput }

        val flattenedSerializer = JwsTypedSerializerTemplate(
            JwsFlattened.Raw.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )
        flattened.forEach { typed ->
            val encoded = joseCompliantSerializer.encodeToString(flattenedSerializer, typed)
            encoded shouldBe joseCompliantSerializer.encodeToString(typed.jws)
            joseCompliantSerializer.decodeFromString(flattenedSerializer, encoded) shouldBe typed
        }
        val generalSerializer = JwsTypedSerializerTemplate(
            JwsGeneral.Raw.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )
        val encoded = joseCompliantSerializer.encodeToString(generalSerializer, general)
        encoded shouldBe joseCompliantSerializer.encodeToString(general.jws)
        joseCompliantSerializer.decodeFromString(generalSerializer, encoded) shouldBe general
    }

    "sealed typed serializer decodes every concrete JWS form with custom headers" {
        val header = JwsHeaderWrapped(CustomJwsHeader(JwsAlgorithm.Signature.RS256, extension = "private"))
        val compact = JwsCompact.Raw(header.protectedHeader, "{}".encodeToByteArray(), byteArrayOf(1))
        val flattened = compact.toFlattened()
        val general = listOf(flattened).toGeneral()
        val serializer = JwsTypedSerializerTemplate(
            JwsRaw.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )

        listOf(compact, flattened, general).forEach { wire ->
            val encoded = joseCompliantSerializer.encodeToString(JwsRaw.serializer(), wire)
            val typed = joseCompliantSerializer.decodeFromString(serializer, encoded)
            typed.jws shouldBe wire
            when (typed) {
                is JwsCompact -> typed.wrappedHeader shouldBe header
                is JwsFlattened -> typed.wrappedHeader shouldBe header
                is JwsGeneral -> typed.wrappedHeaders shouldBe listOf(header)
            }
            joseCompliantSerializer.encodeToString(serializer, typed) shouldBe encoded
        }
    }

    "explicit typed serializers customize decoded views while preserving wire data" {
        val payloadSerializer = object : JsonTransformingSerializer<JsonObject>(JsonObject.serializer()) {
            override fun transformDeserialize(element: JsonElement): JsonElement =
                JsonObject(element.jsonObject + ("decoded" to JsonPrimitive(true)))
        }
        val headerSerializer = object : JsonTransformingSerializer<CustomJwsHeader>(CustomJwsHeader.serializer()) {
            override fun transformDeserialize(element: JsonElement): JsonElement =
                JsonObject(element.jsonObject + ("extension" to JsonPrimitive("decoded")))
        }
        val compact = JwsCompact.Raw(
            """{ "alg": "RS256", "extension": "wire" }""".encodeToByteArray(),
            """{ "sub": "alice" }""".encodeToByteArray(),
            byteArrayOf(1, 2, 3),
        )
        val flattened = compact.toFlattened()
        val general = listOf(flattened).toGeneral()
        val expectedPayload = JsonObject(mapOf("sub" to JsonPrimitive("alice"), "decoded" to JsonPrimitive(true)))
        val expectedHeader = CustomJwsHeader(JwsAlgorithm.Signature.RS256, extension = "decoded")
        val serializer = JwsTypedSerializerTemplate(JwsRaw.serializer(), payloadSerializer, headerSerializer)

        listOf(
            compact.typed(payloadSerializer, headerSerializer),
            flattened.typed(payloadSerializer, headerSerializer),
            general.typed(payloadSerializer, headerSerializer),
        ).forEach { typed ->
            typed.payload shouldBe expectedPayload
            when (typed) {
                is JwsCompact -> listOf(typed.header)
                is JwsFlattened -> listOf(typed.header)
                is JwsGeneral -> typed.headers
            } shouldBe listOf(expectedHeader)
            val encoded = joseCompliantSerializer.encodeToString(JwsRaw.serializer(), typed.jws)
            joseCompliantSerializer.decodeFromString(serializer, encoded) shouldBe typed
            joseCompliantSerializer.encodeToString(serializer, typed) shouldBe encoded
        }

        val lenientFormat = Json(joseCompliantSerializer) { isLenient = true }
        val lenientCompact = compact.copy(plainPayload = """{sub:"alice"}""".encodeToByteArray())
        val lenientFlattened = lenientCompact.toFlattened()
        val lenientGeneral = listOf(lenientFlattened).toGeneral()
        listOf(
            lenientCompact.typed(payloadSerializer, headerSerializer, lenientFormat),
            lenientFlattened.typed(payloadSerializer, headerSerializer, lenientFormat),
            lenientGeneral.typed(payloadSerializer, headerSerializer, lenientFormat),
        ).forEach { it.payload shouldBe expectedPayload }
    }

    "raw JWS accepts duplicate fragments but typed decoding rejects them" {
        val flattened = JwsFlattened.Raw(
            plainProtectedHeader = """{"alg":"RS256","extension":"one"}""".encodeToByteArray(),
            unprotectedHeader = JsonObject(mapOf("extension" to JsonPrimitive("two"))),
            plainPayload = "{}".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )
        val result = runCatching { flattened.typed<CustomJwsHeader, JsonObject>() }
        result.shouldBeFailure().shouldBeInstanceOf<IllegalArgumentException>()
            .message.shouldContain("Duplicate keys: extension")
    }
}
