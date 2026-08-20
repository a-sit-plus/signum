package at.asitplus.signum.indispensable.josef

import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

val JwsHeaderPartsTest by matrixSuite {
    "protected and unprotected JSON objects form an exact partition" {
        val metadata = "bWV0YWRhdGE"
        val unprotectedMembers = listOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.VC_TYPE_METADATA,
        )
        val header = JwsHeader(
            keyId = "did:example:signer",
            type = "vc+sd-jwt",
            algorithm = JwsAlgorithm.Signature.ES256,
            contentType = "application/example+json",
            vcTypeMetadata = setOf(metadata),
        )

        val protectedHeader = header.protectedPart(unprotectedMembers)
        val unprotectedHeader = header.unprotectedPart(unprotectedMembers)

        protectedHeader shouldBe JsonObject(
            mapOf(
                JwsHeader.SerialNames.TYPE to JsonPrimitive("vc+sd-jwt"),
                JwsHeader.SerialNames.ALGORITHM to JsonPrimitive("ES256"),
                JwsHeader.SerialNames.CONTENT_TYPE to JsonPrimitive("application/example+json"),
            )
        )
        unprotectedHeader shouldBe JsonObject(
            mapOf(
                JwsHeader.SerialNames.KEY_ID to JsonPrimitive("did:example:signer"),
                JwsHeader.SerialNames.VC_TYPE_METADATA to JsonArray(listOf(JsonPrimitive(metadata))),
            )
        )
        protectedHeader.keys.intersect(unprotectedHeader.keys) shouldBe emptySet()
    }

    "encoded fragments reconstruct the header and expose member placement on JWS" {
        val unprotectedMembers = listOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.CONTENT_TYPE,
        )
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "did:example:signer",
            contentType = "application/example+json",
        )
        val protectedHeader = header.protectedPart(unprotectedMembers)
        val encodedProtectedHeader = protectedHeader.toProtectedHeaderBytes()
        val unprotectedHeader = header.unprotectedPart(unprotectedMembers)

        Json.parseToJsonElement(encodedProtectedHeader.decodeToString()) shouldBe protectedHeader
        encodedProtectedHeader.toProtectedHeaderJsonObject() shouldBe protectedHeader

        val reconstructed = JwsHeader.fromParts(
            protectedHeader = encodedProtectedHeader,
            unprotectedHeader = unprotectedHeader,
        )
        val flattened = JwsFlattened(
            plainProtectedHeader = encodedProtectedHeader,
            unprotectedHeader = unprotectedHeader,
            plainPayload = byteArrayOf(1),
            plainSignature = byteArrayOf(2),
        )

        reconstructed shouldBe JwsHeaderWrapped(header, unprotectedMembers)
        flattened.jwsHeader shouldBe JwsHeaderWrapped(header, unprotectedMembers)
    }

    "duplicate names across protected and unprotected headers are rejected" {
        val exception = runCatching {
            JwsHeader.fromJsonObjects(
                protectedHeader = JsonObject(mapOf(JwsHeader.SerialNames.KEY_ID to JsonPrimitive("protected"))),
                unprotectedHeader = JsonObject(mapOf(JwsHeader.SerialNames.KEY_ID to JsonPrimitive("unprotected"))),
            )
        }

        exception.shouldBeFailure() shouldBe IllegalArgumentException("Duplicate keys: kid")
    }

    "header equality is independent of member placement" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            keyId = "did:example:signer",
        )
        val protectedJws = JwsFlattened(
            jwsHeader = JwsHeaderWrapped(header),
            payload = byteArrayOf(1),
        ) { byteArrayOf(2) }
        val partlyUnprotectedJws = JwsFlattened(
            jwsHeader = JwsHeaderWrapped(
                header,
                listOf(JwsHeader.SerialNames.KEY_ID),
            ),
            payload = byteArrayOf(1),
        ) { byteArrayOf(2) }

        partlyUnprotectedJws.jwsHeader.header shouldBe protectedJws.jwsHeader.header
        partlyUnprotectedJws.jwsHeader shouldNotBe protectedJws.jwsHeader
    }

    "compact JWS protects every header member" {
        var signerCalled = false

        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            keyId = "did:example:signer",
        )
        val compact = JwsCompact.invoke(
            protectedHeader = header,
            payload = "payload".encodeToByteArray(),
        ) {
            signerCalled = true
            byteArrayOf(1)
        }

        signerCalled shouldBe true
        compact.jwsHeader shouldBe JwsHeaderWrapped(header)
    }
}
