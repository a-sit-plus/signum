package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

val JwsCustomHeaderTest by matrixSuite {
    "custom typed views preserve the exact compact bytes through conversions and serialization" {
        val protectedBytes = """{ "extension": "private", "kid": "custom-key", "alg": "RS256" }"""
            .encodeToByteArray()
        val payloadBytes = """{ "sub": "alice" }""".encodeToByteArray()
        val compact = JwsCompact(protectedBytes, payloadBytes, byteArrayOf(1, 2, 3))
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
            JwsCompactStringSerializer, JsonObject.serializer(), CustomJwsHeader.serializer()
        )
        val encoded = joseCompliantSerializer.encodeToString(serializer, typed)
        encoded shouldBe joseCompliantSerializer.encodeToString(JwsCompactStringSerializer, compact)
        val decoded = joseCompliantSerializer.decodeFromString(serializer, encoded)
        decoded shouldBe typed
        JwsCompact.parse<JsonObject, CustomJwsHeader>(compact.toString()).getOrThrow().third shouldBe typed.wrappedHeader
        JwsCompactTyped<JsonObject, CustomJwsHeader>(compact.toString()) shouldBe typed
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
            val jws = JwsFlattened(header, bytes) { input ->
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
            JwsFlattened.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )
        flattened.forEach { typed ->
            val encoded = joseCompliantSerializer.encodeToString(flattenedSerializer, typed)
            encoded shouldBe joseCompliantSerializer.encodeToString(typed.jws)
            joseCompliantSerializer.decodeFromString(flattenedSerializer, encoded) shouldBe typed
        }
        val generalSerializer = JwsTypedSerializerTemplate(
            JwsGeneral.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )
        val encoded = joseCompliantSerializer.encodeToString(generalSerializer, general)
        encoded shouldBe joseCompliantSerializer.encodeToString(general.jws)
        joseCompliantSerializer.decodeFromString(generalSerializer, encoded) shouldBe general
    }

    "sealed typed serializer decodes every concrete JWS form with custom headers" {
        val header = JwsHeaderWrapped(CustomJwsHeader(JwsAlgorithm.Signature.RS256, extension = "private"))
        val compact = JwsCompact(header, "{}".encodeToByteArray()) { byteArrayOf(1) }
        val flattened = compact.toJwsFlattened()
        val general = listOf(flattened).toJwsGeneral()
        val serializer = JwsTypedSerializerTemplate(
            JWS.serializer(), JsonObject.serializer(), CustomJwsHeader.serializer()
        )

        listOf(compact, flattened, general).forEach { wire ->
            val encoded = joseCompliantSerializer.encodeToString(JWS.serializer(), wire)
            val typed = joseCompliantSerializer.decodeFromString(serializer, encoded)
            typed.jws shouldBe wire
            when (typed) {
                is JwsCompactTyped -> typed.wrappedHeader shouldBe header
                is JwsFlattenedTyped -> typed.wrappedHeader shouldBe header
                is JwsGeneralTyped -> typed.wrappedHeaders shouldBe listOf(header)
            }
            joseCompliantSerializer.encodeToString(serializer, typed) shouldBe encoded
        }
    }

    "compact signing rejects represented unprotected members before invoking the signer" {
        val header = JwsHeaderWrapped(
            CustomJwsHeader(JwsAlgorithm.Signature.RS256, extension = "private"), setOf("extension")
        )
        var called = false
        val result = runCatching {
            JwsCompact(header, "{}".encodeToByteArray()) {
                called = true
                byteArrayOf(1)
            }
        }
        result.shouldBeFailure().message.shouldContain("does not support unprotected")
        called shouldBe false
    }

    "raw JWS accepts duplicate fragments but typed decoding rejects them" {
        val flattened = JwsFlattened(
            plainProtectedHeader = """{"alg":"RS256","extension":"one"}""".encodeToByteArray(),
            unprotectedHeader = JsonObject(mapOf("extension" to JsonPrimitive("two"))),
            plainPayload = "{}".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )
        val result = runCatching { flattened.typed<JsonObject, CustomJwsHeader>() }
        result.shouldBeFailure() shouldBe IllegalArgumentException("Duplicate keys: extension")
    }
}
