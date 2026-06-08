package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

private val jweTypedPayload = JwtBaseClaims(
    issuer = "https://issuer.example",
    subject = "alice",
    audience = "test-suite",
    jwtId = "jwt-1",
)

val JweTypedTest by testSuite {
    "getPayload decrypts the supplied JWE and decodes the typed plaintext" {
        val jwe = sampleFlattenedJwe()
        var observedJwe: JWE? = null

        val decoded = JweTyped.getPayload<JwtBaseClaims>(
            decryptor = {
                observedJwe = it
                jweTypedPayload.toPlaintext()
            },
            jwe = jwe,
        )

        decoded.getOrThrow() shouldBe jweTypedPayload
        observedJwe shouldBe jwe
    }

    "decrypted builds a typed wrapper and delegates string form to the encrypted JWE" {
        val compact = JweCompact(
            protectedHeader = JweHeader(
                algorithm = JweAlgorithm.A128KW,
                encryption = JweEncryption.A128GCM,
                keyId = "typed-compact",
            ),
            payload = jweTypedPayload,
        ) { _, _ ->
            JWE.EncryptionOutput(
                iv = byteArrayOf(1),
                cipherText = byteArrayOf(2),
                encryptedKey = byteArrayOf(3),
                authenticationTag = byteArrayOf(4),
            )
        }
        var observedJwe: JWE? = null

        val typed: JweCompactTyped<JwtBaseClaims> = compact.decrypted {
            observedJwe = it
            jweTypedPayload.toPlaintext()
        }

        typed.jwe shouldBe compact
        typed.payload shouldBe jweTypedPayload
        typed.toString() shouldBe compact.toString()
        observedJwe shouldBe compact
    }

    "decrypted compact JWE can carry a compact JWS payload" {
        val jwtBaseClaims = JwtBaseClaims(
            issuer = "https://issuer.example",
            subject = "alice",
            audience = "test-suite",
            jwtId = "jwt-1",
        )
        val signedJwt = JwsTyped(
            protectedHeader = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "JWT",
                keyId = "nested-jws",
            ),
            payload = jwtBaseClaims,
        ) {
            byteArrayOf(6, 7, 8, 9)
        }.jws
        val encryptedJwt = JweCompact(
            protectedHeader = JweHeader(
                algorithm = JweAlgorithm.A128KW,
                encryption = JweEncryption.A128GCM,
                contentType = "JWT",
                keyId = "nested-jwe",
            ),
            payload = signedJwt,
        ) { _, payload ->
            payload shouldBe signedJwt
            JWE.EncryptionOutput(
                iv = byteArrayOf(1),
                cipherText = byteArrayOf(2),
                encryptedKey = byteArrayOf(3),
                authenticationTag = byteArrayOf(4),
            )
        }
        val decryptedPlaintext = joseCompliantSerializer.encodeToString(JWS.serializer(), signedJwt)
            .encodeToByteArray()

        val typed: JweCompactTyped<JWS> = encryptedJwt.decrypted { decryptedPlaintext }
        val compactPayload = typed.payload.shouldBeInstanceOf<JwsCompact>()

        typed.jwe shouldBe encryptedJwt
        compactPayload shouldBe signedJwt
        compactPayload.getPayload<JwtBaseClaims>().getOrThrow() shouldBe jwtBaseClaims
    }

    "getPayload returns a failure when decryption or deserialization fails" {
        val jwe = sampleFlattenedJwe()

        val decryptionFailure = JweTyped.getPayload<JwtBaseClaims>(
            decryptor = { throw IllegalStateException("ciphertext rejected") },
            jwe = jwe,
        )
        val deserializationFailure = JweTyped.getPayload<JwtBaseClaims>(
            decryptor = { "not-json".encodeToByteArray() },
            jwe = jwe,
        )

        runCatching { decryptionFailure.getOrThrow() }
            .shouldBeFailure().message.shouldContain("ciphertext rejected")
        runCatching { deserializationFailure.getOrThrow() }
            .shouldBeFailure().message.shouldContain("Expected start of the object")
    }
}

private fun sampleFlattenedJwe(): JweFlattened = JweFlattened(
    protectedHeader = JweHeader.Part(
        algorithm = JweAlgorithm.A128KW,
        encryption = JweEncryption.A128GCM,
    ),
    encryptedKey = byteArrayOf(2),
    initializationVector = byteArrayOf(3),
    ciphertext = byteArrayOf(4),
    authenticationTag = byteArrayOf(5),
)

private fun JwtBaseClaims.toPlaintext(): ByteArray =
    joseCompliantSerializer.encodeToString(JwtBaseClaims.serializer(), this).encodeToByteArray()
