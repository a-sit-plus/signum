package at.asitplus.signum.indispensable.josef

import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

val JwsRawHeaderPartsTest by matrixSuite {
    "protected and unprotected JSON objects form an exact partition" {
        val metadata = "bWV0YWRhdGE"
        val unprotectedMembers = setOf(
            JwsHeaderMonolith.SerialNames.KEY_ID,
            JwsHeaderMonolith.SerialNames.VC_TYPE_METADATA,
        )
        val header = JwsHeaderMonolith(
            keyId = "did:example:signer",
            type = "vc+sd-jwt",
            algorithm = JwsAlgorithm.Signature.ES256,
            contentType = "application/example+json",
            vcTypeMetadata = setOf(metadata),
        )
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)

        val protectedHeader = wrappedHeader.protectedHeader.toProtectedHeaderJsonObject()
        val unprotectedHeader = wrappedHeader.unprotectedHeader

        protectedHeader shouldBe JsonObject(
            mapOf(
                JwsHeaderMonolith.SerialNames.TYPE to JsonPrimitive("vc+sd-jwt"),
                JwsHeaderMonolith.SerialNames.ALGORITHM to JsonPrimitive("ES256"),
                JwsHeaderMonolith.SerialNames.CONTENT_TYPE to JsonPrimitive("application/example+json"),
            )
        )
        unprotectedHeader shouldBe JsonObject(
            mapOf(
                JwsHeaderMonolith.SerialNames.KEY_ID to JsonPrimitive("did:example:signer"),
                JwsHeaderMonolith.SerialNames.VC_TYPE_METADATA to JsonArray(listOf(JsonPrimitive(metadata))),
            )
        )
    }

    "encoded fragments reconstruct headers with protected and unprotected thumbprints" {
        val unprotectedMembers = setOf(
            JwsHeaderMonolith.SerialNames.KEY_ID,
            JwsHeaderMonolith.SerialNames.CONTENT_TYPE,
            JwsHeaderMonolith.SerialNames.CERTIFICATE_SHA1_THUMBPRINT,
        )
        val header = JwsHeaderMonolith(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "did:example:signer",
            contentType = "application/example+json",
            certificateSha1Thumbprint = byteArrayOf(1, 2, 3),
            certificateSha256Thumbprint = byteArrayOf(4, 5, 6),
        )
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)
        val encodedProtectedHeader = wrappedHeader.protectedHeader
        val protectedHeader = encodedProtectedHeader.toProtectedHeaderJsonObject()
        val unprotectedHeader = wrappedHeader.unprotectedHeader

        protectedHeader.keys shouldBe setOf(
            JwsHeaderMonolith.SerialNames.TYPE,
            JwsHeaderMonolith.SerialNames.ALGORITHM,
            JwsHeaderMonolith.SerialNames.CERTIFICATE_SHA256_THUMBPRINT,
        )
        unprotectedHeader.keys shouldBe setOf(
            JwsHeaderMonolith.SerialNames.KEY_ID,
            JwsHeaderMonolith.SerialNames.CONTENT_TYPE,
            JwsHeaderMonolith.SerialNames.CERTIFICATE_SHA1_THUMBPRINT,
        )
        val reconstructedHeader =
            JwsHeaderWrapped.fromParts<JwsHeaderMonolith>(encodedProtectedHeader, unprotectedHeader)

        reconstructedHeader shouldBe wrappedHeader
    }

    "duplicate names across protected and unprotected headers are rejected" {
        val exception = runCatching {
            JwsHeaderWrapped.fromJsonObjects<JwsHeaderMonolith>(
                protectedHeader = JsonObject(mapOf(JwsHeaderMonolith.SerialNames.KEY_ID to JsonPrimitive("protected"))),
                unprotectedHeader = JsonObject(mapOf(JwsHeaderMonolith.SerialNames.KEY_ID to JsonPrimitive("unprotected"))),
            )
        }

        exception.shouldBeFailure().shouldBeInstanceOf<IllegalArgumentException>()
            .message.shouldContain("Duplicate keys: kid")
    }
}
