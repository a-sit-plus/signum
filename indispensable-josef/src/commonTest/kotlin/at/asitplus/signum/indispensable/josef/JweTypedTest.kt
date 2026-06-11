package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.Serializable

private val jweTypedPayload = JwtBaseClaims(
    issuer = "https://issuer.example",
    subject = "alice",
    audience = "test-suite",
    jwtId = "jwt-1",
)

private val jweTypedAdditionalAuthenticatedData = JweTypedAdditionalAuthenticatedData(
    transactionId = "txn-1",
    sequence = 7,
)

val JweTypedTest by matrixSuite {
    "getPayload decrypts the supplied JWE and decodes the typed plaintext" {
        val jwe = sampleFlattenedJwe()
        var observedJwe: JWE? = null

        val decoded = jwe.getPayload<JwtBaseClaims> {
            observedJwe = it
            jweTypedPayload.toPlaintext()
        }

        decoded.getOrThrow() shouldBe jweTypedPayload
        observedJwe shouldBe jwe
    }

    "decrypted builds a typed wrapper and delegates string form to the encrypted JWE" {
        val compactHeader = JweHeader(
            algorithm = JweAlgorithm.A128KW,
            encryption = JweEncryption.A128GCM,
            keyId = "typed-compact",
        )
        val compact = JweCompact(
            encryptionInput = JweEncryptor.EncryptionInput(
                protectedHeader = compactHeader.toPart(),
                sharedUnprotectedHeader = null,
                recipientUnprotectedHeader = null,
                payload = jweTypedPayload.toPlaintext(),
                additionalAuthenticatedData = null,
            ),
        ) {
            JweEncryptor.EncryptionOutput(
                iv = byteArrayOf(1),
                cipherText = byteArrayOf(2),
                encryptedKey = byteArrayOf(3),
                authenticationTag = byteArrayOf(4),
            )
        }
        var observedJwe: JWE? = null

        val typed: JweCompactTyped<JwtBaseClaims, Unit> = compact.decrypted {
            observedJwe = it
            jweTypedPayload.toPlaintext()
        }

        typed.jwe shouldBe compact
        typed.payload shouldBe jweTypedPayload
        typed.additionalAuthenticatedData shouldBe null
        typed.toString() shouldBe compact.toString()
        observedJwe shouldBe compact
    }

    "decrypted flattened JWE decodes typed additional authenticated data" {
        val additionalAuthenticatedData = joseCompliantSerializer.encodeToString(
            JweTypedAdditionalAuthenticatedData.serializer(),
            jweTypedAdditionalAuthenticatedData,
        ).encodeToByteArray()
        val flattened = sampleFlattenedJwe(additionalAuthenticatedData = additionalAuthenticatedData)
        var observedJwe: JWE? = null

        val typed: JweFlattenedTyped<JwtBaseClaims, JweTypedAdditionalAuthenticatedData> = flattened.decrypted {
            observedJwe = it
            jweTypedPayload.toPlaintext()
        }

        typed.jwe shouldBe flattened
        typed.payload shouldBe jweTypedPayload
        typed.additionalAuthenticatedData shouldBe jweTypedAdditionalAuthenticatedData
        observedJwe shouldBe flattened
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
        val encryptedJwtHeader = JweHeader(
            algorithm = JweAlgorithm.A128KW,
            encryption = JweEncryption.A128GCM,
            contentType = "JWT",
            keyId = "nested-jwe",
        )
        val encryptedJwt = JweCompact(
            encryptionInput = JweEncryptor.EncryptionInput(
                protectedHeader = encryptedJwtHeader.toPart(),
                sharedUnprotectedHeader = null,
                recipientUnprotectedHeader = null,
                payload = joseCompliantSerializer.encodeToString(JWS.serializer(), signedJwt).encodeToByteArray(),
                additionalAuthenticatedData = null,
            ),
        ) {
            joseCompliantSerializer.decodeFromString<JWS>(it.payload.decodeToString()) shouldBe signedJwt
            JweEncryptor.EncryptionOutput(
                iv = byteArrayOf(1),
                cipherText = byteArrayOf(2),
                encryptedKey = byteArrayOf(3),
                authenticationTag = byteArrayOf(4),
            )
        }
        val decryptedPlaintext = joseCompliantSerializer.encodeToString(JWS.serializer(), signedJwt)
            .encodeToByteArray()

        val typed: JweCompactTyped<JWS, Unit> = encryptedJwt.decrypted { decryptedPlaintext }
        val compactPayload = typed.payload.shouldBeInstanceOf<JwsCompact>()

        typed.jwe shouldBe encryptedJwt
        typed.additionalAuthenticatedData shouldBe null
        compactPayload shouldBe signedJwt
        compactPayload.getPayload<JwtBaseClaims>().getOrThrow() shouldBe jwtBaseClaims
    }

    "getPayload returns a failure when decryption or deserialization fails" {
        val jwe = sampleFlattenedJwe()

        val decryptionFailure = jwe.getPayload<JwtBaseClaims> {
            throw IllegalStateException("ciphertext rejected")
        }
        val deserializationFailure = jwe.getPayload<JwtBaseClaims> {
            "not-json".encodeToByteArray()
        }

        runCatching { decryptionFailure.getOrThrow() }
            .shouldBeFailure().message.shouldContain("ciphertext rejected")
        runCatching { deserializationFailure.getOrThrow() }
            .shouldBeFailure().message.shouldContain("Expected start of the object")
    }
}

@Serializable
private data class JweTypedAdditionalAuthenticatedData(
    val transactionId: String,
    val sequence: Int,
)

private fun sampleFlattenedJwe(
    additionalAuthenticatedData: ByteArray? = null,
): JweFlattened = JweFlattened(
    plainProtectedHeader = JweProtectedHeaderSerializer.encodeToByteArrayOrNull(
        JweHeader.Part(
            algorithm = JweAlgorithm.A128KW,
            encryption = JweEncryption.A128GCM,
        )
    )!!,
    encryptedKey = byteArrayOf(2),
    additionalAuthenticatedData = additionalAuthenticatedData,
    initializationVector = byteArrayOf(3),
    ciphertext = byteArrayOf(4),
    authenticationTag = byteArrayOf(5),
)

private fun JwtBaseClaims.toPlaintext(): ByteArray =
    joseCompliantSerializer.encodeToString(JwtBaseClaims.serializer(), this).encodeToByteArray()
