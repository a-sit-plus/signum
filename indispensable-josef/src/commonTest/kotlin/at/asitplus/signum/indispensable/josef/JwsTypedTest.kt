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

val JwsRawTypedTest by matrixSuite {
    "compact typed wrappers can be constructed and reopened from compact JWS" {
        val header = JwsHeaderMonolith(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-compact",
        )
        val expectedPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray()
        val wrappedHeader = JwsHeaderWrapped(header)
        val expectedProtectedHeader = wrappedHeader.protectedHeader
        val typedCompact = JwsCompact(
            jws = JwsCompact.Raw(
                plainProtectedHeader = expectedProtectedHeader,
                plainPayload = expectedPayload,
                plainSignature = byteArrayOf(1, 2, 3, 4),
            ),
            payload = payload,
            wrappedHeader = wrappedHeader,
            signature = JwsRaw.getSignature(header.algorithm, byteArrayOf(1, 2, 3, 4)),
        )

        typedCompact.payload shouldBe payload
        typedCompact.jws.plainPayload shouldBe expectedPayload
        typedCompact.jws.signatureInput shouldBe JwsRaw.getSignatureInput(expectedProtectedHeader, expectedPayload)
        typedCompact.toString() shouldBe typedCompact.jws.toString()

        typedCompact.jws.typed<JsonObject, JwsHeaderMonolith>() shouldBe typedCompact
        JwsTyped<JsonObject, JwsHeaderMonolith>(typedCompact.toString()) shouldBe typedCompact
    }

    "compact and flattened typed wrappers convert without changing the payload view" {
        val wrappedHeader = JwsHeaderWrapped(
            JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-roundtrip",
            )
        )
        val typedCompact = JwsCompact(
            jws = JwsCompact.Raw(
                plainProtectedHeader = wrappedHeader.protectedHeader,
                plainPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray(),
                plainSignature = byteArrayOf(9, 8, 7, 6),
            ),
            payload = payload,
            wrappedHeader = wrappedHeader,
            signature = JwsRaw.getSignature(wrappedHeader.header.algorithm, byteArrayOf(9, 8, 7, 6)),
        )

        val typedFlattened = typedCompact.toFlattened()
        val reparsedCompact = typedFlattened.toCompact()

        typedFlattened.payload shouldBe payload
        typedFlattened.jws shouldBe typedCompact.jws.toFlattened()
        reparsedCompact shouldBe typedCompact
    }

    "typed serializer template roundtrips compact JWS with typed payload" {
        val serializer = JwsTypedSerializerTemplate(
            JwsCompactRawStringSerializer,
            JsonObject.serializer(),
            JwsHeaderMonolith.serializer(),
        )
        val wrappedHeader = JwsHeaderWrapped(
            JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-serializer",
            )
        )
        val typedCompact = JwsCompact(
            jws = JwsCompact.Raw(
                plainProtectedHeader = wrappedHeader.protectedHeader,
                plainPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray(),
                plainSignature = byteArrayOf(5, 6, 7, 8),
            ),
            payload = payload,
            wrappedHeader = wrappedHeader,
            signature = JwsRaw.getSignature(wrappedHeader.header.algorithm, byteArrayOf(5, 6, 7, 8)),
        )

        val serialized = joseCompliantSerializer.encodeToString(serializer, typedCompact)
        val reparsed = joseCompliantSerializer.decodeFromString(serializer, serialized)

        reparsed shouldBe typedCompact
        reparsed.payload shouldBe payload
    }

    "flattened typed wrappers can be created from split headers and existing flattened JWS" {
        val unprotectedMembers = setOf(
            JwsHeaderMonolith.SerialNames.KEY_ID,
            JwsHeaderMonolith.SerialNames.CONTENT_TYPE,
        )
        val header = JwsHeaderMonolith(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-flattened",
            contentType = "application/example+json",
        )
        val expectedPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray()
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)
        val expectedProtectedHeader = wrappedHeader.protectedHeader
            .takeUnless { it.toProtectedHeaderJsonObject().isEmpty() }
        val typedFlattened = JwsFlattened(
            jws = JwsFlattened.Raw(
                plainProtectedHeader = expectedProtectedHeader,
                unprotectedHeader = wrappedHeader.unprotectedHeader,
                plainPayload = expectedPayload,
                plainSignature = byteArrayOf(4, 3, 2, 1),
            ),
            payload = payload,
            wrappedHeader = wrappedHeader,
            signature = JwsRaw.getSignature(header.algorithm, byteArrayOf(4, 3, 2, 1)),
        )

        typedFlattened.payload shouldBe payload
        typedFlattened.jws.plainPayload shouldBe expectedPayload
        typedFlattened.jws.unprotectedHeader shouldBe wrappedHeader.unprotectedHeader
        typedFlattened.wrappedHeader shouldBe wrappedHeader
        typedFlattened.jws.signatureInput shouldBe JwsRaw.getSignatureInput(expectedProtectedHeader, expectedPayload)
        typedFlattened.toString() shouldBe typedFlattened.jws.toString()

        typedFlattened.jws.typed<JsonObject, JwsHeaderMonolith>() shouldBe typedFlattened
    }

    "general typed wrappers can be assembled from flattened signatures and expanded again" {
        val firstHeader = JwsHeaderWrapped(
            header = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
                keyId = "kid-1",
            ),
            unprotectedMembers = setOf(JwsHeaderMonolith.SerialNames.KEY_ID),
        )
        val first = JwsFlattened(
            jws = JwsFlattened.Raw(
                plainProtectedHeader = firstHeader.protectedHeader,
                unprotectedHeader = firstHeader.unprotectedHeader,
                plainPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray(),
                plainSignature = byteArrayOf(1, 1, 1, 1),
            ),
            payload = payload,
            wrappedHeader = firstHeader,
            signature = JwsRaw.getSignature(firstHeader.header.algorithm, byteArrayOf(1, 1, 1, 1)),
        )
        val secondHeader = JwsHeaderWrapped(
            header = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
                keyId = "kid-2",
            ),
            unprotectedMembers = setOf(JwsHeaderMonolith.SerialNames.TYPE),
        )
        val second = JwsFlattened(
            jws = JwsFlattened.Raw(
                plainProtectedHeader = secondHeader.protectedHeader,
                unprotectedHeader = secondHeader.unprotectedHeader,
                plainPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray(),
                plainSignature = byteArrayOf(2, 2, 2, 2),
            ),
            payload = payload,
            wrappedHeader = secondHeader,
            signature = JwsRaw.getSignature(secondHeader.header.algorithm, byteArrayOf(2, 2, 2, 2)),
        )

        val typedGeneral = listOf(first.jws, second.jws).toGeneral().typed<JsonObject, JwsHeaderMonolith>()

        typedGeneral.payload shouldBe payload
        typedGeneral.jws shouldBe listOf(first.jws, second.jws).toGeneral()
        typedGeneral.wrappedHeaders.map { it.unprotectedHeaderMembers } shouldBe listOf(
            setOf(JwsHeaderMonolith.SerialNames.KEY_ID),
            setOf(JwsHeaderMonolith.SerialNames.TYPE),
        )
        typedGeneral.toString() shouldBe typedGeneral.jws.toString()
        typedGeneral.toFlattened() shouldBe listOf(first, second)

        typedGeneral.jws.typed<JsonObject, JwsHeaderMonolith>() shouldBe typedGeneral
    }
}
