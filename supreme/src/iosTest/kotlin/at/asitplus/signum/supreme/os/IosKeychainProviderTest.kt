package at.asitplus.signum.supreme.os

import at.asitplus.shouldSucceed
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.supreme.azString
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds


val IosKeychainProviderTest by matrixSuite {
    "Authentication timeout readback" - {
        data(
            listOf(null, Duration.ZERO, 10.seconds),
            nameFn = { it?.toString() ?: "no authentication" },
        ) test { authenticationTimeout ->
            val metadata = IosKeyMetadata(
                attestation = null,
                rawUnlockTimeout = authenticationTimeout,
                algSpecific = IosKeyAlgSpecificMetadata.ECDSA(setOf(Digest.SHA256)),
            ).let { Json.decodeFromString<IosKeyMetadata>(Json.encodeToString(it)) }
            val publicKey = with(CryptoPublicKey.EC) {
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

    "Creating a key with an alias that already exists" - {

        "fails but leaves the existing key untouched when the new config is broken" {
            val alias = Random.azString(32)
            try {
                // an existing key lives under this alias
                val original = IosKeychainProvider.createSigningKey(alias).getOrThrow()

                // attempt to create another key with the same alias, using a config that throws
                val secondAttempt = IosKeychainProvider.createSigningKey(alias) {
                    throw IllegalStateException("intentionally broken config")
                }
                secondAttempt.isFailure shouldBe true

                // the original key must still be present and unchanged
                val recovered = IosKeychainProvider.getSignerForKey(alias)
                recovered.shouldSucceed()
                recovered.getOrThrow().publicKey shouldBe original.publicKey
            } finally {
                IosKeychainProvider.deleteSigningKey(alias)
            }
        }

        "fails but leaves the existing key untouched when the new config is valid" {
            val alias = Random.azString(32)
            try {
                val original = IosKeychainProvider.createSigningKey(alias).getOrThrow()

                val secondAttempt = IosKeychainProvider.createSigningKey(alias)
                secondAttempt.isFailure shouldBe true

                val recovered = IosKeychainProvider.getSignerForKey(alias)
                recovered.shouldSucceed()
                recovered.getOrThrow().publicKey shouldBe original.publicKey
            } finally {
                IosKeychainProvider.deleteSigningKey(alias)
            }
        }
    }
}
