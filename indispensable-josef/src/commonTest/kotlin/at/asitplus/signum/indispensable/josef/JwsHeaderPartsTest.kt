package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

val JwsHeaderPartsTest by matrixSuite {
    "protected and unprotected JSON objects form an exact partition" {
        val metadata = "bWV0YWRhdGE"
        val unprotectedMembers = setOf(
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
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)

        val protectedHeader = wrappedHeader.toProtectedHeader().toProtectedHeaderJsonObject()
        val unprotectedHeader = wrappedHeader.toUnprotectedHeader()

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
        val unprotectedMembers = setOf(
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.CONTENT_TYPE,
            JwsHeader.SerialNames.CERTIFICATE_SHA1_THUMBPRINT,
        )
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "did:example:signer",
            contentType = "application/example+json",
            certificateSha1Thumbprint = byteArrayOf(1, 2, 3),
            certificateSha256Thumbprint = byteArrayOf(4, 5, 6),
        )
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)
        val encodedProtectedHeader = wrappedHeader.toProtectedHeader()
        val protectedHeader = encodedProtectedHeader.toProtectedHeaderJsonObject()
        val unprotectedHeader = wrappedHeader.toUnprotectedHeader()

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
        val flattened = JwsFlattened(
            plainProtectedHeader = encodedProtectedHeader,
            unprotectedHeader = unprotectedHeader,
            plainPayload = byteArrayOf(1),
            plainSignature = byteArrayOf(2),
        )

        flattened.wrappedHeader shouldBe wrappedHeader
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

    "member placement is set-like and stable through serialization" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            keyId = "did:example:signer",
            contentType = "application/example+json",
        )
        val wrappedHeader = JwsHeaderWrapped(
            header,
            linkedSetOf(
                JwsHeader.SerialNames.CONTENT_TYPE,
                JwsHeader.SerialNames.KEY_ID,
            ),
        )
        val flattened = JwsFlattened(
            wrappedHeader = wrappedHeader,
            payload = byteArrayOf(1),
        ) { byteArrayOf(2) }
        val reparsed = joseCompliantSerializer.decodeFromString<JwsFlattened>(
            joseCompliantSerializer.encodeToString(flattened)
        )

        reparsed.wrappedHeader shouldBe wrappedHeader
        reparsed.wrappedHeader.header shouldBe header
    }

    "effective member placement ignores names absent from the modeled header" {
        val header = JwsHeader(algorithm = JwsAlgorithm.Signature.RS256)
        val withAbsentMember = JwsHeaderWrapped(
            header,
            setOf(JwsHeader.SerialNames.KEY_ID),
        )
        val withoutAbsentMember = JwsHeaderWrapped(header)

        withAbsentMember.unprotectedMembers shouldBe setOf(JwsHeader.SerialNames.KEY_ID)
        withAbsentMember.effectiveUnprotectedMembers shouldBe emptySet()
        withAbsentMember.toProtectedHeader() shouldBe withoutAbsentMember.toProtectedHeader()
        withAbsentMember.toUnprotectedHeader() shouldBe withoutAbsentMember.toUnprotectedHeader()
        withAbsentMember shouldBe withoutAbsentMember
        withAbsentMember.hashCode() shouldBe withoutAbsentMember.hashCode()
    }

    "fully protected flattened JWS omits the unprotected header" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            keyId = "did:example:signer",
        )
        val wrappedHeader = JwsHeaderWrapped(header)
        val flattened = JwsFlattened.invoke(
            wrappedHeader = wrappedHeader,
            payload = "payload".encodeToByteArray(),
        ) { byteArrayOf(1) }
        val serialized = joseCompliantSerializer.encodeToJsonElement(flattened).jsonObject

        flattened.wrappedHeader shouldBe wrappedHeader
        flattened.unprotectedHeader shouldBe null
        (JWS.SerialNames.HEADER in serialized) shouldBe false
    }
}
