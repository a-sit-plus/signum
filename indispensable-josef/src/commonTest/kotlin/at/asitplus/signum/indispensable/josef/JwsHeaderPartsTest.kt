package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

val JwsHeaderPartsTest by matrixSuite {
    "full JWS header can be converted to its protected JSON object" {
        val header = JwsHeader(
            keyId = "did:example:signer",
            type = "vc+sd-jwt",
            algorithm = JwsAlgorithm.Signature.ES256,
            contentType = "application/example+json",
            certificateSha1Thumbprint = byteArrayOf(1, 2, 3),
            certificateSha256Thumbprint = byteArrayOf(4, 5, 6),
            vcTypeMetadata = setOf("bWV0YWRhdGE"),
        )

        val part = header.protectedPart()

        part shouldBe joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(header)
        )
        JwsHeader.fromJsonObjects(protectedHeader = part) shouldBe header
    }

    "split headers combine into a valid JWS header" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.ES256,
            type = "vc+sd-jwt",
            keyId = "did:example:signer",
            vcTypeMetadata = setOf("bWV0YWRhdGE"),
            unprotectedMembers = listOf(
                JwsHeader.SerialNames.KEY_ID,
                JwsHeader.SerialNames.VC_TYPE_METADATA,
            ),
        )

        val combined = JwsHeader.fromJsonObjects(
            protectedHeader = header.protectedPart(),
            unprotectedHeader = header.unprotectedPart(),
        )

        combined.algorithm shouldBe JwsAlgorithm.Signature.ES256
        combined.type shouldBe "vc+sd-jwt"
        combined.keyId shouldBe "did:example:signer"
        combined.vcTypeMetadata shouldBe setOf("bWV0YWRhdGE")
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

    "encoded protected header bytes can be merged with unprotected fields" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "did:example:signer",
            contentType = "application/example+json",
            unprotectedMembers = listOf(
                JwsHeader.SerialNames.KEY_ID,
                JwsHeader.SerialNames.CONTENT_TYPE,
            ),
        )
        val protectedHeader = header.protectedPart()
        val unprotectedHeader = header.unprotectedPart()

        val combined = JwsHeader.fromParts(
            protectedHeader = protectedHeader.toProtectedHeaderBytes(),
            unprotectedHeader = unprotectedHeader,
        )

        combined shouldBe JwsHeader.fromJsonObjects(protectedHeader, unprotectedHeader)
    }

    "duplicate names across encoded protected and unprotected headers are rejected" {
        val protectedHeader = JsonObject(
            mapOf(
                JwsHeader.SerialNames.ALGORITHM to JsonPrimitive("RS256"),
                JwsHeader.SerialNames.KEY_ID to JsonPrimitive("protected"),
            )
        ).toProtectedHeaderBytes()

        val exception = runCatching {
            JwsHeader.fromParts(
                protectedHeader = protectedHeader,
                unprotectedHeader = JsonObject(
                    mapOf(JwsHeader.SerialNames.KEY_ID to JsonPrimitive("unprotected"))
                ),
            )
        }

        exception.shouldBeFailure() shouldBe IllegalArgumentException("Duplicate keys: kid")
    }

    "flattened JWS splits headers according to unprotected members" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.ES256,
            type = "application/example+jwt",
            vcTypeMetadata = setOf("bWV0YWRhdGE"),
            unprotectedMembers = listOf(JwsHeader.SerialNames.VC_TYPE_METADATA),
        )
        val payload = "payload".encodeToByteArray()

        val flattened = JwsFlattened.invoke(
            jwsHeader = header,
            payload = payload,
        ) {
            validEs256SignatureFixture
        }

        flattened.jwsHeader shouldBe header
    }

    "compact JWS accepts full headers and serializes their protected part" {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.ES256,
            type = "application/example+jwt",
            keyId = "did:example:signer",
            vcTypeMetadata = setOf("bWV0YWRhdGE"),
        )
        val payload = "payload".encodeToByteArray()

        val compact = JwsCompact.invoke(
            protectedHeader = header,
            payload = payload,
        ) {
            validEs256SignatureFixture
        }

        compact.jwsHeader shouldBe header
        compact.plainProtectedHeader shouldBe header.protectedPart().toProtectedHeaderBytes()
    }

    "protected header bytes are raw header json bytes" {
        val protectedHeader = JwsHeader(
            algorithm = JwsAlgorithm.Signature.ES256,
            type = "application/example+jwt",
        ).protectedPart()

        val encoded = protectedHeader.toProtectedHeaderBytes()
        val expected = joseCompliantSerializer.encodeToString(JsonObject.serializer(), protectedHeader)
            .encodeToByteArray()

        encoded shouldBe expected
        encoded.toProtectedHeaderJsonObject() shouldBe protectedHeader
    }
}

// RFC 7515 Appendix A.6 ES256 signature; reused so constructors get a parseable raw ES256 signature.
private val validEs256SignatureFixture =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        .decodeToByteArray(Base64UrlStrict)
