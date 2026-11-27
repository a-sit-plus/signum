@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.supreme.os

import at.asitplus.signum.dsl.IosSignerConfiguration
import at.asitplus.signum.dsl.signer
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.digest
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.supreme.azString
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds


val IosKeychainProviderTest by matrixSuite {
    "Opaque backend IDs are stable namespaced identifiers" - {
        "accepts a reverse-DNS identifier" {
            validateOpaqueBackendId("com.example.crypto.mldsa") shouldBe "com.example.crypto.mldsa"
        }

        "rejects empty, unqualified, and malformed identifiers" {
            listOf("", "x", "abc", "has space", ".starts-with-dot").forEach { id ->
                runCatching { validateOpaqueBackendId(id) }.isFailure shouldBe true
            }
        }
    }

    "Opaque signing policy" - {
        "rejects a reopened key whose canonical SPKI differs" {
            val expected = with(EcdsaPublicKey) { ECCurve.SECP_256_R_1.generator.asPublicKey() }
            val different = with(EcdsaPublicKey) { ECCurve.SECP_384_R_1.generator.asPublicKey() }
            shouldThrow<IllegalArgumentException> {
                requireOpaquePublicKeyMatch(expected.asn1.toDer(), different)
            }
        }

        "requires fresh per-use authentication and scopes timed reuse to key identity" {
            val identity = "alias\u0000backend\u0000record"
            shouldReuseAuthentication(Duration.ZERO, identity, identity, 0.seconds) shouldBe false
            shouldReuseAuthentication(10.seconds, identity, identity, 9.seconds) shouldBe true
            shouldReuseAuthentication(10.seconds, identity, identity, 10.seconds) shouldBe false
            shouldReuseAuthentication(10.seconds, identity, "other-record", 1.seconds) shouldBe false
        }

        "hashes and stores the identical App Attest client-data bytes" {
            val publicKey = with(EcdsaPublicKey) { ECCurve.SECP_256_R_1.generator.asPublicKey() }
            val challenge = byteArrayOf(1, 2, 3, 4)
            val (clientData, digest) = prepareAppAttestBinding(publicKey, challenge)
            clientData.contentEquals(IosHomebrewAttestation.ClientData(publicKey, challenge).prepareDigestInput()) shouldBe true
            digest.contentEquals(Digest.SHA256.digest(clientData)) shouldBe true
        }
    }

    "Authentication timeout readback" - {
        data(
            listOf(null, Duration.ZERO, 10.seconds),
            nameFn = { it?.toString() ?: "no authentication" },
        ) test { authenticationTimeout ->
            val metadata = IosKeyMetadata(
                attestation = null,
                rawUnlockTimeout = authenticationTimeout,
                algSpecific = Json.encodeToJsonElement(IosKeyAlgSpecificMetadata.ECDSA(setOf(Digest.SHA256))),
            ).let { Json.decodeFromString<IosKeyMetadata>(Json.encodeToString(it)) }
            val publicKey = with(EcdsaPublicKey) {
                ECCurve.SECP_256_R_1.generator.asPublicKey()
            }
            val signer = IosSigner.ECDSA(
                alias = "restored-key",
                publicKey = publicKey,
                metadata = metadata,
                config = IosSignerConfiguration(),
            )

            signer.authenticationTimeout shouldBe authenticationTimeout
            signer.needsAuthentication shouldBe (authenticationTimeout != null)
            signer.needsAuthenticationForEveryUse shouldBe (authenticationTimeout == Duration.ZERO)
        }
    }

    "SecKey signer setup failure deletes only the generated key pair" {
        val alias = Random.azString(32)
        try {
            shouldThrow<IllegalStateException> {
                IosKeychainProvider.createSigningKey(alias) {
                    signer { error("signer setup failed after generation") }
                }
            }
            shouldThrow<NoSuchElementException> { IosKeychainProvider.getSignerForKey(alias) }
            IosKeychainProvider.createSigningKey(alias).alias shouldBe alias
        } finally {
            IosKeychainProvider.deleteSigningKey(alias)
        }
    }

    "Creating a key with an alias that already exists" - {

        "fails but leaves the existing key untouched when the new config is broken" {
            val alias = Random.azString(32)
            try {
                // an existing key lives under this alias
                val original = IosKeychainProvider.createSigningKey(alias)

                // attempt to create another key with the same alias, using a config that throws
                val secondAttempt = runCatching { IosKeychainProvider.createSigningKey(alias) {
                    throw IllegalStateException("intentionally broken config")
                }}
                secondAttempt.isFailure shouldBe true

                // the original key must still be present and unchanged
                IosKeychainProvider.getSignerForKey(alias).publicKey shouldBe original.publicKey
            } finally {
                IosKeychainProvider.deleteSigningKey(alias)
            }
        }

        "fails but leaves the existing key untouched when the new config is valid" {
            val alias = Random.azString(32)
            try {
                val original = IosKeychainProvider.createSigningKey(alias)

                val secondAttempt = runCatching { IosKeychainProvider.createSigningKey(alias) }
                secondAttempt.isFailure shouldBe true

                IosKeychainProvider.getSignerForKey(alias).publicKey shouldBe original.publicKey
            } finally {
                IosKeychainProvider.deleteSigningKey(alias)
            }
        }
    }
}
