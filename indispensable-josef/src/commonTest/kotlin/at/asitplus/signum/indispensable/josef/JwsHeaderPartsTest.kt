package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val JwsHeaderPartsTest by testSuite {
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

        exception.exceptionOrNull() shouldBe IllegalArgumentException("Duplicate keys: kid")
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

        exception.exceptionOrNull() shouldBe IllegalArgumentException("Duplicate keys: kid")
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
        var capturedAlgorithm: JwsAlgorithm? = null

        val flattened = JwsFlattened.invoke(
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            payload = payload,
        ) { algorithm, _ ->
            capturedAlgorithm = algorithm
            byteArrayOf(1, 2, 3)
        }

        capturedAlgorithm shouldBe JwsAlgorithm.Signature.ES256
        flattened.jwsHeader shouldBe JwsHeader.fromParts(protectedHeader, unprotectedHeader)
    }

    "compact JWS accepts typed protected header" {
        val protectedHeader = JwsHeader.Part(
            algorithm = JwsAlgorithm.Signature.ES256,
            type = "application/example+jwt",
        )
        val payload = "payload".encodeToByteArray()
        var capturedAlgorithm: JwsAlgorithm? = null

        val compact = JwsCompact.invoke(
            protectedHeader = protectedHeader,
            payload = payload,
        ) { algorithm, _ ->
            capturedAlgorithm = algorithm
            byteArrayOf(1, 2, 3)
        }

        capturedAlgorithm shouldBe JwsAlgorithm.Signature.ES256
        compact.jwsHeader shouldBe JwsHeader.fromParts(protectedHeader, null)
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
