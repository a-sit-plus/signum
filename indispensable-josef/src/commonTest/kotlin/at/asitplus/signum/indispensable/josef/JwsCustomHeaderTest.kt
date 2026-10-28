package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
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
        val typed = compact.typed<JsonObject, CustomJwsHeader>()

        (typed.jws === compact) shouldBe true
        typed.wrappedHeader.header.extension shouldBe "private"
        typed.signature.joseBytes shouldBe compact.plainSignature
        val converted = typed.toJwsFlattenedTyped().toJwsCompactTyped()
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
        JwsCompact.Raw.parse<JsonObject, CustomJwsHeader>(compact.toString()).getOrThrow().third shouldBe typed.wrappedHeader
        JwsCompact<JsonObject, CustomJwsHeader>(compact.toString()) shouldBe typed
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
            var capturedInput: ByteArray? = null
            val jws = JwsFlattenedTyped.Raw(header, bytes) { input ->
                capturedInput = input
                signatures[index]
            }
            capturedInput shouldBe jws.signatureInput
            jws.typed<JsonObject, CustomJwsHeader>()
        }
        val general = flattened.map { it.jws }.toJwsGeneral().typed<JsonObject, CustomJwsHeader>()

        general.payload shouldBe payload
        general.wrappedHeaders shouldBe headers
        general.signatures.map { it.joseBytes } shouldBe signatures
        general.toJwsFlattenedTyped() shouldBe flattened
        general.jws.signatureInputs shouldBe flattened.map { it.jws.signatureInput }

        val flattenedSerializer = JwsTypedSerializerTemplate(
            JwsFlattenedTyped.Raw.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )
        flattened.forEach { typed ->
            val encoded = joseCompliantSerializer.encodeToString(flattenedSerializer, typed)
            encoded shouldBe joseCompliantSerializer.encodeToString(typed.jws)
            joseCompliantSerializer.decodeFromString(flattenedSerializer, encoded) shouldBe typed
        }
        val generalSerializer = JwsTypedSerializerTemplate(
            JwsRawGeneral.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )
        val encoded = joseCompliantSerializer.encodeToString(generalSerializer, general)
        encoded shouldBe joseCompliantSerializer.encodeToString(general.jws)
        joseCompliantSerializer.decodeFromString(generalSerializer, encoded) shouldBe general
    }

    "sealed typed serializer decodes every concrete JWS form with custom headers" {
        val header = JwsHeaderWrapped(CustomJwsHeader(JwsAlgorithm.Signature.RS256, extension = "private"))
        val compact = JwsCompact.Raw(header, "{}".encodeToByteArray()) { byteArrayOf(1) }
        val flattened = compact.toJwsFlattened()
        val general = listOf(flattened).toJwsGeneral()
        val serializer = JwsTypedSerializerTemplate(
            JwsRaw.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )

        listOf(compact, flattened, general).forEach { wire ->
            val encoded = joseCompliantSerializer.encodeToString(JwsRaw.serializer(), wire)
            val typed = joseCompliantSerializer.decodeFromString(serializer, encoded)
            typed.jws shouldBe wire
            when (typed) {
                is JwsCompact -> typed.wrappedHeader shouldBe header
                is JwsFlattenedTyped -> typed.wrappedHeader shouldBe header
                is JwsGeneralTyped -> typed.wrappedHeaders shouldBe listOf(header)
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
        val flattened = compact.toJwsFlattened()
        val general = listOf(flattened).toJwsGeneral()
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
                is JwsFlattenedTyped -> listOf(typed.header)
                is JwsGeneralTyped -> typed.headers
            } shouldBe listOf(expectedHeader)
            val encoded = joseCompliantSerializer.encodeToString(JwsRaw.serializer(), typed.jws)
            joseCompliantSerializer.decodeFromString(serializer, encoded) shouldBe typed
            joseCompliantSerializer.encodeToString(serializer, typed) shouldBe encoded
        }

        val lenientFormat = Json(joseCompliantSerializer) { isLenient = true }
        val lenientCompact = compact.copy(plainPayload = """{sub:"alice"}""".encodeToByteArray())
        val lenientFlattened = lenientCompact.toJwsFlattened()
        val lenientGeneral = listOf(lenientFlattened).toJwsGeneral()
        listOf(
            lenientCompact.typed(payloadSerializer, headerSerializer, lenientFormat),
            lenientFlattened.typed(payloadSerializer, headerSerializer, lenientFormat),
            lenientGeneral.typed(payloadSerializer, headerSerializer, lenientFormat),
        ).forEach { it.payload shouldBe expectedPayload }
    }

    "compact signing rejects represented unprotected members before invoking the signer" {
        val header = JwsHeaderWrapped(
            CustomJwsHeader(JwsAlgorithm.Signature.RS256, extension = "private"), setOf("extension")
        )
        var called = false
        val result = runCatching {
            JwsCompact.Raw(header, "{}".encodeToByteArray()) {
                called = true
                byteArrayOf(1)
            }
        }
        result.shouldBeFailure().message.shouldContain("does not support unprotected")
        called shouldBe false
    }

    "raw JWS accepts duplicate fragments but typed decoding rejects them" {
        val flattened = JwsFlattenedTyped.Raw(
            plainProtectedHeader = """{"alg":"RS256","extension":"one"}""".encodeToByteArray(),
            unprotectedHeader = JsonObject(mapOf("extension" to JsonPrimitive("two"))),
            plainPayload = "{}".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )
        val result = runCatching { flattened.typed<JsonObject, CustomJwsHeader>() }
        result.shouldBeFailure() shouldBe IllegalArgumentException("Duplicate keys: extension")
    }
}
