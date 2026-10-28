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
        val unprotectedMembers = setOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.CONTENT_TYPE,
        )
        val header = SigningHeader(
            keyId = "did:example:signer",
            type = "vc+sd-jwt",
            algorithm = JwsAlgorithm.Signature.ES256,
            contentType = "application/example+json",
            extension = "custom-value",
            crit = listOf("extension"),
        )
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)

        val protectedHeader = wrappedHeader.protectedHeader.toProtectedHeaderJsonObject()
        val unprotectedHeader = wrappedHeader.unprotectedHeader

        protectedHeader shouldBe JsonObject(
            mapOf(
                JwsHeader.SerialNames.TYPE to JsonPrimitive("vc+sd-jwt"),
                JwsHeader.SerialNames.ALGORITHM to JsonPrimitive("ES256"),
                "extension" to JsonPrimitive("custom-value"),
                "crit" to JsonArray(listOf(JsonPrimitive("extension"))),
            )
        )
        unprotectedHeader shouldBe JsonObject(
            mapOf(
                JwsHeader.SerialNames.KEY_ID to JsonPrimitive("did:example:signer"),
                JwsHeader.SerialNames.CONTENT_TYPE to JsonPrimitive("application/example+json"),
            )
        )
    }

    "encoded fragments reconstruct headers with protected and unprotected thumbprints" {
        val unprotectedMembers = setOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.CONTENT_TYPE,
            JwsHeader.SerialNames.CERTIFICATE_SHA1_THUMBPRINT,
        )
        val header = SigningHeader(
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
            JwsHeader.SerialNames.TYPE,
            JwsHeader.SerialNames.ALGORITHM,
            JwsHeader.SerialNames.CERTIFICATE_SHA256_THUMBPRINT,
        )
        unprotectedHeader.keys shouldBe setOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.CONTENT_TYPE,
            JwsHeader.SerialNames.CERTIFICATE_SHA1_THUMBPRINT,
        )
        val reconstructedHeader =
            JwsHeaderWrapped.fromParts<SigningHeader>(encodedProtectedHeader, unprotectedHeader)

        reconstructedHeader.header.certificateSha1Thumbprint shouldBe header.certificateSha1Thumbprint
        reconstructedHeader.header.certificateSha256Thumbprint shouldBe header.certificateSha256Thumbprint
        reconstructedHeader.protectedHeader.toProtectedHeaderJsonObject() shouldBe protectedHeader
        reconstructedHeader.unprotectedHeader shouldBe unprotectedHeader
    }

    "duplicate names across protected and unprotected headers are rejected" {
        val exception = runCatching {
            JwsHeaderWrapped.fromJsonObjects<SigningHeader>(
                protectedHeader = JsonObject(mapOf(JwsHeader.SerialNames.KEY_ID to JsonPrimitive("protected"))),
                unprotectedHeader = JsonObject(mapOf(JwsHeader.SerialNames.KEY_ID to JsonPrimitive("unprotected"))),
            )
        }

        exception.shouldBeFailure().shouldBeInstanceOf<IllegalArgumentException>()
            .message.shouldContain("Duplicate keys: kid")
    }
}
