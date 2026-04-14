package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

val JwsHeaderPartsTest by testSuite {
    "full JWS header can be converted to a typed header part" {
        val header = JwsHeader(
            keyId = "did:example:signer",
            type = "vc+sd-jwt",
            algorithm = JwsAlgorithm.Signature.ES256,
            contentType = "application/example+json",
            certificateSha1Thumbprint = byteArrayOf(1, 2, 3),
            certificateSha256Thumbprint = byteArrayOf(4, 5, 6),
            vcTypeMetadata = setOf("bWV0YWRhdGE"),
        )

        val part = header.toPart()

        part shouldBe JwsHeader.Part(
            keyId = "did:example:signer",
            type = "vc+sd-jwt",
            algorithm = JwsAlgorithm.Signature.ES256,
            contentType = "application/example+json",
            certificateSha1Thumbprint = byteArrayOf(1, 2, 3),
            certificateSha256Thumbprint = byteArrayOf(4, 5, 6),
            vcTypeMetadata = setOf("bWV0YWRhdGE"),
        )
        JwsHeader.fromParts(protectedHeader = part) shouldBe header
    }

    "split headers combine into a valid JWS header" {
        val protectedHeader = JwsHeader.Part(
            algorithm = JwsAlgorithm.Signature.ES256,
            type = "vc+sd-jwt",
        )
        val unprotectedHeader = JwsHeader.Part(
            keyId = "did:example:signer",
            vcTypeMetadata = setOf("bWV0YWRhdGE"),
        )

        val combined = JwsHeader.fromParts(
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
        )

        combined.algorithm shouldBe JwsAlgorithm.Signature.ES256
        combined.type shouldBe "vc+sd-jwt"
        combined.keyId shouldBe "did:example:signer"
        combined.vcTypeMetadata shouldBe setOf("bWV0YWRhdGE")
    }

    "duplicate names across protected and unprotected headers are rejected" {
        val exception = runCatching {
            JwsHeader.fromParts(
                protectedHeader = JwsHeader.Part(keyId = "protected"),
                unprotectedHeader = JwsHeader.Part(keyId = "unprotected"),
            )
        }

        exception.shouldBeFailure() shouldBe IllegalArgumentException("Duplicate keys: kid")
    }

    "encoded protected header bytes can be merged with unprotected fields" {
        val protectedHeader = JwsHeader.Part(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
        )
        val unprotectedHeader = JwsHeader.Part(
            keyId = "did:example:signer",
            contentType = "application/example+json",
        )

        val combined = JwsHeader.fromParts(
            protectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(protectedHeader),
            unprotectedHeader = unprotectedHeader,
        )

        combined shouldBe JwsHeader.fromParts(protectedHeader, unprotectedHeader)
    }

    "duplicate names across encoded protected and unprotected headers are rejected" {
        val protectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(
            JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "protected",
            )
        )

        val exception = runCatching {
            JwsHeader.fromParts(
                protectedHeader = protectedHeader,
                unprotectedHeader = JwsHeader.Part(keyId = "unprotected"),
            )
        }

        exception.shouldBeFailure() shouldBe IllegalArgumentException("Duplicate keys: kid")
    }

    "flattened JWS accepts typed header parts" {
        val protectedHeader = JwsHeader.Part(
            algorithm = JwsAlgorithm.Signature.ES256,
            type = "application/example+jwt",
        )
        val unprotectedHeader = JwsHeader.Part(
            vcTypeMetadata = setOf("bWV0YWRhdGE"),
        )
        val payload = "payload".encodeToByteArray()

        val flattened = JwsFlattened.invoke(
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            payload = payload,
        ) {
            validEs256SignatureFixture
        }

        flattened.jwsHeader shouldBe JwsHeader.fromParts(protectedHeader, unprotectedHeader)
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
        compact.plainProtectedHeader shouldBe
                JwsProtectedHeaderSerializer.encodeToByteArray(header.toPart())
    }

    "protected header bytes are raw header json bytes" {
        val protectedHeader = JwsHeader.Part(
            algorithm = JwsAlgorithm.Signature.ES256,
            type = "application/example+jwt",
        )

        val encoded = JwsProtectedHeaderSerializer.encodeToByteArray(protectedHeader)
        val expected = joseCompliantSerializer.encodeToString(JwsHeader.Part.serializer(), protectedHeader)
            .encodeToByteArray()

        encoded shouldBe expected
        JwsProtectedHeaderSerializer.decodeFromByteArray(encoded) shouldBe protectedHeader
    }
}

// RFC 7515 Appendix A.6 ES256 signature; reused so constructors get a parseable raw ES256 signature.
private val validEs256SignatureFixture =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        .decodeToByteArray(Base64UrlStrict)
