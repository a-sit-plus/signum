package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
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

val JwsTypedTest by testSuite {
    "compact typed wrappers can be built from payloads and reopened from compact JWS" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-compact",
        )
        val expectedPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray()
        val expectedProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(header.toPart())
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

        typedCompact.jws.typed<JsonObject, JwsCompact>() shouldBe typedCompact
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

    "flattened typed wrappers can be created from header fragments and existing flattened JWS" {
        val protectedHeader = JwsHeader.Part(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
        )
        val unprotectedHeader = JwsHeader.Part(
            keyId = "kid-flattened",
            contentType = "application/example+json",
        )
        val expectedPayload = joseCompliantSerializer.encodeToString<JsonObject>(payload).encodeToByteArray()
        val expectedProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArrayOrNull(protectedHeader)
        var capturedSignatureInput: ByteArray? = null

        val typedFlattened: JwsFlattenedTyped<JsonObject> = JwsTyped(
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            payload = payload,
        ) { signatureInput ->
            capturedSignatureInput = signatureInput
            byteArrayOf(4, 3, 2, 1)
        }

        typedFlattened.payload shouldBe payload
        typedFlattened.jws.plainPayload shouldBe expectedPayload
        typedFlattened.jws.unprotectedHeader shouldBe unprotectedHeader
        capturedSignatureInput shouldBe JWS.getSignatureInput(expectedProtectedHeader, expectedPayload)
        typedFlattened.toString() shouldBe typedFlattened.jws.toString()

        typedFlattened.jws.typed<JsonObject, JwsFlattened>() shouldBe typedFlattened
    }

    "general typed wrappers can be assembled from flattened signatures and expanded again" {
        val first: JwsFlattenedTyped<JsonObject> = JwsTyped(
            protectedHeader = JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
            ),
            unprotectedHeader = JwsHeader.Part(keyId = "kid-1"),
            payload = payload,
        ) {
            byteArrayOf(1, 1, 1, 1)
        }
        val second: JwsFlattenedTyped<JsonObject> = JwsTyped(
            protectedHeader = JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
            ),
            unprotectedHeader = JwsHeader.Part(keyId = "kid-2"),
            payload = payload,
        ) {
            byteArrayOf(2, 2, 2, 2)
        }

        val typedGeneral: JwsGeneralTyped<JsonObject> = JwsTyped(listOf(first.jws, second.jws))

        typedGeneral.payload shouldBe payload
        typedGeneral.jws shouldBe listOf(first.jws, second.jws).toJwsGeneral()
        typedGeneral.toString() shouldBe typedGeneral.jws.toString()
        typedGeneral.toJwsFlattenedTyped() shouldBe listOf(first, second)

        typedGeneral.jws.typed<JsonObject, JwsGeneral>() shouldBe typedGeneral
    }
}