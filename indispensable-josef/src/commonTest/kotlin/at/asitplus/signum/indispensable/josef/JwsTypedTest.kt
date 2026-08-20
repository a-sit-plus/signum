package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

val payload = JsonObject(
    content = mapOf(
        "issuer" to JsonPrimitive("https://issuer.example"),
        "subject" to JsonPrimitive("alice"),
        "admin" to JsonPrimitive(true),
    )
)

val JwsTypedTest by matrixSuite {
    "compact typed wrappers can be built from payloads and reopened from compact JWS" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-compact",
        )
        val expectedPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray()
        val expectedProtectedHeader = JwsHeaderWrapped(header).toProtectedHeader()
        var capturedSignatureInput: ByteArray? = null

        val typedCompact: JwsCompactTyped<JsonObject> = JwsTyped(
            protectedHeader = header,
            payload = payload,
        ) { signatureInput ->
            capturedSignatureInput = signatureInput
            byteArrayOf(1, 2, 3, 4)
        }

        typedCompact.payload shouldBe payload
        typedCompact.jws.plainPayload shouldBe expectedPayload
        capturedSignatureInput shouldBe JWS.getSignatureInput(expectedProtectedHeader, expectedPayload)
        typedCompact.toString() shouldBe typedCompact.jws.toString()

        typedCompact.jws.typed<JwsCompact, JsonObject>() shouldBe typedCompact
        JwsTyped<JsonObject>(typedCompact.toString()) shouldBe typedCompact
    }

    "compact and flattened typed wrappers convert without changing the payload view" {
        val typedCompact: JwsCompactTyped<JsonObject> = JwsTyped(
            protectedHeader = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-roundtrip",
            ),
            payload = payload,
        ) {
            byteArrayOf(9, 8, 7, 6)
        }

        val typedFlattened = typedCompact.toJwsFlattenedTyped()
        val reparsedCompact = typedFlattened.toJwsCompactTyped()

        typedFlattened.payload shouldBe payload
        typedFlattened.jws shouldBe typedCompact.jws.toJwsFlattened()
        reparsedCompact shouldBe typedCompact
    }

    "typed serializer template roundtrips compact JWS with typed payload" {
        val serializer = JwsTypedSerializerTemplate(
            JwsCompactStringSerializer,
            JsonObject.serializer(),
        )
        val typedCompact: JwsCompactTyped<JsonObject> = JwsTyped(
            protectedHeader = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-serializer",
            ),
            payload = payload,
        ) {
            byteArrayOf(5, 6, 7, 8)
        }

        val serialized = joseCompliantSerializer.encodeToString(serializer, typedCompact)
        val reparsed = joseCompliantSerializer.decodeFromString(serializer, serialized)

        reparsed shouldBe typedCompact
        reparsed.payload shouldBe payload
    }

    "flattened typed wrappers can be created from split headers and existing flattened JWS" {
        val unprotectedMembers = setOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.CONTENT_TYPE,
        )
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-flattened",
            contentType = "application/example+json",
        )
        val expectedPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray()
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)
        val expectedProtectedHeader = wrappedHeader.toProtectedHeader()
            .takeUnless { it.toProtectedHeaderJsonObject().isEmpty() }
        var capturedSignatureInput: ByteArray? = null

        val typedFlattened: JwsFlattenedTyped<JsonObject> = JwsTyped.flattened(
            wrappedHeader = wrappedHeader,
            payload = payload,
        ) { signatureInput ->
            capturedSignatureInput = signatureInput
            byteArrayOf(4, 3, 2, 1)
        }

        typedFlattened.payload shouldBe payload
        typedFlattened.jws.plainPayload shouldBe expectedPayload
        typedFlattened.jws.unprotectedHeader shouldBe wrappedHeader.toUnprotectedHeader()
        typedFlattened.jws.wrappedHeader shouldBe wrappedHeader
        capturedSignatureInput shouldBe JWS.getSignatureInput(expectedProtectedHeader, expectedPayload)
        typedFlattened.toString() shouldBe typedFlattened.jws.toString()

        typedFlattened.jws.typed<JwsFlattened, JsonObject>() shouldBe typedFlattened
    }

    "general typed wrappers can be assembled from flattened signatures and expanded again" {
        val first: JwsFlattenedTyped<JsonObject> = JwsTyped.flattened(
            wrappedHeader = JwsHeaderWrapped(
                header = JwsHeader(
                    algorithm = JwsAlgorithm.Signature.RS256,
                    type = "application/example+jws",
                    keyId = "kid-1",
                ),
                unprotectedMembers = setOf(JwsHeader.SerialNames.KEY_ID),
            ),
            payload = payload,
        ) {
            byteArrayOf(1, 1, 1, 1)
        }
        val second: JwsFlattenedTyped<JsonObject> = JwsTyped.flattened(
            wrappedHeader = JwsHeaderWrapped(
                header = JwsHeader(
                    algorithm = JwsAlgorithm.Signature.RS256,
                    type = "application/example+jws",
                    keyId = "kid-2",
                ),
                unprotectedMembers = setOf(JwsHeader.SerialNames.TYPE),
            ),
            payload = payload,
        ) {
            byteArrayOf(2, 2, 2, 2)
        }

        val typedGeneral: JwsGeneralTyped<JsonObject> = JwsTyped(listOf(first.jws, second.jws))

        typedGeneral.payload shouldBe payload
        typedGeneral.jws shouldBe listOf(first.jws, second.jws).toJwsGeneral()
        typedGeneral.jws.wrappedHeaders.map { it.unprotectedMembers } shouldBe listOf(
            setOf(JwsHeader.SerialNames.KEY_ID),
            setOf(JwsHeader.SerialNames.TYPE),
        )
        typedGeneral.toString() shouldBe typedGeneral.jws.toString()
        typedGeneral.toJwsFlattenedTyped() shouldBe listOf(first, second)

        typedGeneral.jws.typed<JwsGeneral, JsonObject>() shouldBe typedGeneral
    }
}
