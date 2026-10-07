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
    "compact typed wrappers can be constructed and reopened from compact JWS" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-compact",
        )
        val expectedPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray()
        val wrappedHeader = JwsHeaderWrapped(header)
        val expectedProtectedHeader = wrappedHeader.toProtectedHeader()
        val typedCompact = JwsCompactTyped(
            jws = JwsCompact(
                plainProtectedHeader = expectedProtectedHeader,
                plainPayload = expectedPayload,
                plainSignature = byteArrayOf(1, 2, 3, 4),
            ),
            payload = payload,
            wrappedHeader = wrappedHeader,
            signature = JWS.getSignature(header.algorithm, byteArrayOf(1, 2, 3, 4)),
        )

        typedCompact.payload shouldBe payload
        typedCompact.jws.plainPayload shouldBe expectedPayload
        typedCompact.jws.signatureInput shouldBe JWS.getSignatureInput(expectedProtectedHeader, expectedPayload)
        typedCompact.toString() shouldBe typedCompact.jws.toString()

        typedCompact.jws.typed<JsonObject, JwsHeader>() shouldBe typedCompact
        JwsTyped<JsonObject, JwsHeader>(typedCompact.toString()) shouldBe typedCompact
    }

    "compact and flattened typed wrappers convert without changing the payload view" {
        val wrappedHeader = JwsHeaderWrapped(
            JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-roundtrip",
            )
        )
        val typedCompact = JwsCompactTyped(
            jws = JwsCompact(
                plainProtectedHeader = wrappedHeader.toProtectedHeader(),
                plainPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray(),
                plainSignature = byteArrayOf(9, 8, 7, 6),
            ),
            payload = payload,
            wrappedHeader = wrappedHeader,
            signature = JWS.getSignature(wrappedHeader.header.algorithm, byteArrayOf(9, 8, 7, 6)),
        )

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
            JwsHeader.serializer(),
        )
        val wrappedHeader = JwsHeaderWrapped(
            JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-serializer",
            )
        )
        val typedCompact = JwsCompactTyped(
            jws = JwsCompact(
                plainProtectedHeader = wrappedHeader.toProtectedHeader(),
                plainPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray(),
                plainSignature = byteArrayOf(5, 6, 7, 8),
            ),
            payload = payload,
            wrappedHeader = wrappedHeader,
            signature = JWS.getSignature(wrappedHeader.header.algorithm, byteArrayOf(5, 6, 7, 8)),
        )

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
        val typedFlattened = JwsFlattenedTyped(
            jws = JwsFlattened(
                plainProtectedHeader = expectedProtectedHeader,
                unprotectedHeader = wrappedHeader.toUnprotectedHeader(),
                plainPayload = expectedPayload,
                plainSignature = byteArrayOf(4, 3, 2, 1),
            ),
            payload = payload,
            wrappedHeader = wrappedHeader,
            signature = JWS.getSignature(header.algorithm, byteArrayOf(4, 3, 2, 1)),
        )

        typedFlattened.payload shouldBe payload
        typedFlattened.jws.plainPayload shouldBe expectedPayload
        typedFlattened.jws.unprotectedHeader shouldBe wrappedHeader.toUnprotectedHeader()
        typedFlattened.wrappedHeader shouldBe wrappedHeader
        typedFlattened.jws.signatureInput shouldBe JWS.getSignatureInput(expectedProtectedHeader, expectedPayload)
        typedFlattened.toString() shouldBe typedFlattened.jws.toString()

        typedFlattened.jws.typed<JsonObject, JwsHeader>() shouldBe typedFlattened
    }

    "general typed wrappers can be assembled from flattened signatures and expanded again" {
        val firstHeader = JwsHeaderWrapped(
            header = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
                keyId = "kid-1",
            ),
            unprotectedMembers = setOf(JwsHeader.SerialNames.KEY_ID),
        )
        val first = JwsFlattenedTyped(
            jws = JwsFlattened(
                plainProtectedHeader = firstHeader.toProtectedHeader(),
                unprotectedHeader = firstHeader.toUnprotectedHeader(),
                plainPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray(),
                plainSignature = byteArrayOf(1, 1, 1, 1),
            ),
            payload = payload,
            wrappedHeader = firstHeader,
            signature = JWS.getSignature(firstHeader.header.algorithm, byteArrayOf(1, 1, 1, 1)),
        )
        val secondHeader = JwsHeaderWrapped(
            header = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
                keyId = "kid-2",
            ),
            unprotectedMembers = setOf(JwsHeader.SerialNames.TYPE),
        )
        val second = JwsFlattenedTyped(
            jws = JwsFlattened(
                plainProtectedHeader = secondHeader.toProtectedHeader(),
                unprotectedHeader = secondHeader.toUnprotectedHeader(),
                plainPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray(),
                plainSignature = byteArrayOf(2, 2, 2, 2),
            ),
            payload = payload,
            wrappedHeader = secondHeader,
            signature = JWS.getSignature(secondHeader.header.algorithm, byteArrayOf(2, 2, 2, 2)),
        )

        val typedGeneral = listOf(first.jws, second.jws).toJwsGeneral().typed<JsonObject, JwsHeader>()

        typedGeneral.payload shouldBe payload
        typedGeneral.jws shouldBe listOf(first.jws, second.jws).toJwsGeneral()
        typedGeneral.wrappedHeaders.map { it.unprotectedMembers } shouldBe listOf(
            setOf(JwsHeader.SerialNames.KEY_ID),
            setOf(JwsHeader.SerialNames.TYPE),
        )
        typedGeneral.toString() shouldBe typedGeneral.jws.toString()
        typedGeneral.toJwsFlattenedTyped() shouldBe listOf(first, second)

        typedGeneral.jws.typed<JsonObject, JwsHeader>() shouldBe typedGeneral
    }
}
