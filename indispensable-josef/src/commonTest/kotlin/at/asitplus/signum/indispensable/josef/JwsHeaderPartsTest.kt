package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

val JwsHeaderPartsTest by matrixSuite {
    "encoded header fragments form an exact partition and reconstruct member placement" {
        val metadata = "bWV0YWRhdGE"
        val unprotectedMembers = setOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.VC_TYPE_METADATA,
            JwsHeader.SerialNames.CERTIFICATE_SHA1_THUMBPRINT,
        )
        val header = JwsHeader(
            keyId = "did:example:signer",
            type = "vc+sd-jwt",
            algorithm = JwsAlgorithm.Signature.ES256,
            contentType = "application/example+json",
            certificateSha1Thumbprint = byteArrayOf(1, 2, 3),
            certificateSha256Thumbprint = byteArrayOf(4, 5, 6),
            vcTypeMetadata = setOf(metadata),
        )
        val flattened = JwsFlattened(
            header = header,
            payload = byteArrayOf(1),
            unprotectedMembers = unprotectedMembers,
        ) { ByteArray(64) { 1 } }
        val protectedHeader = flattened.protectedHeader.shouldNotBeNull()
        val unprotectedHeader = flattened.unprotectedHeader.shouldNotBeNull()

        protectedHeader shouldBe JsonObject(
            mapOf(
                JwsHeader.SerialNames.TYPE to JsonPrimitive("vc+sd-jwt"),
                JwsHeader.SerialNames.ALGORITHM to JsonPrimitive("ES256"),
                JwsHeader.SerialNames.CONTENT_TYPE to JsonPrimitive("application/example+json"),
                JwsHeader.SerialNames.CERTIFICATE_SHA256_THUMBPRINT to JsonPrimitive("BAUG"),
            )
        )
        unprotectedHeader shouldBe JsonObject(
            mapOf(
                JwsHeader.SerialNames.KEY_ID to JsonPrimitive("did:example:signer"),
                JwsHeader.SerialNames.VC_TYPE_METADATA to JsonArray(listOf(JsonPrimitive(metadata))),
                JwsHeader.SerialNames.CERTIFICATE_SHA1_THUMBPRINT to JsonPrimitive("AQID"),
            )
        )
        flattened.wrappedHeader.header shouldBe header
        flattened.wrappedHeader.unprotectedMembers shouldBe unprotectedMembers
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

    "member placement ignores names absent from a newly serialized header" {
        val header = JwsHeader(algorithm = JwsAlgorithm.Signature.RS256)
        val withAbsentMember = JwsFlattened(
            header = header,
            payload = byteArrayOf(1),
            unprotectedMembers = setOf(JwsHeader.SerialNames.KEY_ID),
        ) { byteArrayOf(2) }
        val withoutAbsentMember = JwsFlattened(
            header = header,
            payload = byteArrayOf(1),
        ) { byteArrayOf(2) }

        withAbsentMember.unprotectedHeader shouldBe null
        withAbsentMember.plainProtectedHeader shouldBe withoutAbsentMember.plainProtectedHeader
        withAbsentMember.wrappedHeader shouldBe withoutAbsentMember.wrappedHeader
    }

    "fully protected flattened JWS omits the unprotected header" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            keyId = "did:example:signer",
        )
        val flattened = JwsFlattened.invoke(
            header = header,
            payload = "payload".encodeToByteArray(),
        ) { byteArrayOf(1) }
        val serialized = joseCompliantSerializer.encodeToJsonElement(flattened).jsonObject

        flattened.wrappedHeader.header shouldBe header
        flattened.wrappedHeader.unprotectedMembers shouldBe emptySet()
        flattened.unprotectedHeader shouldBe null
        (JWS.SerialNames.HEADER in serialized) shouldBe false
    }
}
