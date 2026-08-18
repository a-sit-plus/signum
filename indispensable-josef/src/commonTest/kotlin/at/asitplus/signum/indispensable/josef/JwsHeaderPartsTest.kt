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
        val header = JwsHeader(
            keyId = "did:example:signer",
            type = "vc+sd-jwt",
            algorithm = JwsAlgorithm.Signature.ES256,
            contentType = "application/example+json",
            vcTypeMetadata = setOf(metadata),
            unprotectedMembers = listOf(
                JwsHeader.SerialNames.KEY_ID,
                JwsHeader.SerialNames.VC_TYPE_METADATA,
            ),
        )

        val protectedHeader = header.protectedPart()
        val unprotectedHeader = header.unprotectedPart()

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

    "encoded fragments reconstruct the header and its member placement" {
        val unprotectedMembers = listOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.CONTENT_TYPE,
        )
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "did:example:signer",
            contentType = "application/example+json",
            unprotectedMembers = unprotectedMembers,
        )
        val protectedHeader = header.protectedPart()
        val encodedProtectedHeader = protectedHeader.toProtectedHeaderBytes()

        Json.parseToJsonElement(encodedProtectedHeader.decodeToString()) shouldBe protectedHeader
        encodedProtectedHeader.toProtectedHeaderJsonObject() shouldBe protectedHeader

        val reconstructed = JwsHeader.fromParts(
            protectedHeader = encodedProtectedHeader,
            unprotectedHeader = header.unprotectedPart(),
        )

        reconstructed shouldBe header
        reconstructed.unprotectedMembers shouldBe unprotectedMembers
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

    "header equality includes protected member placement" {
        val protectedHeader = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            keyId = "did:example:signer",
        )
        val partlyUnprotectedHeader = protectedHeader.copy(
            unprotectedMembers = listOf(JwsHeader.SerialNames.KEY_ID)
        )

        partlyUnprotectedHeader shouldNotBe protectedHeader
        partlyUnprotectedHeader.hashCode() shouldNotBe protectedHeader.hashCode()
    }

    "compact JWS rejects unprotected members before signing" {
        var signerCalled = false

        val exception = runCatching {
            JwsCompact.invoke(
                protectedHeader = JwsHeader(
                    algorithm = JwsAlgorithm.Signature.RS256,
                    keyId = "did:example:signer",
                    unprotectedMembers = listOf(JwsHeader.SerialNames.KEY_ID),
                ),
                payload = "payload".encodeToByteArray(),
            ) {
                signerCalled = true
                byteArrayOf(1)
            }
        }

        exception.shouldBeFailure() shouldBe
                IllegalArgumentException("Compact Serialization does not support unprotected header members")
        signerCalled shouldBe false
    }
}
