package at.asitplus.signum.examples

import at.asitplus.signum.dsl.*
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.os.IosKeychainProvider
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.seconds
import kotlin.random.Random

val IosSupremeExamples by matrixSuite {
    "Platform configuration" {
        // --8<-- [start:supreme-ios-configuration]
        val serverChallenge = ByteArray(32) { it.toByte() } // fixed test fixture; obtain a fresh challenge from your server!
        val configureKey: IosSigningKeyConfiguration.() -> Unit = {
            ec { curve = ECCurve.SECP_256_R_1 }
            hardware {
                backing = REQUIRED
                attestation { challenge = serverChallenge }
                protection {
                    timeout = 5.seconds
                    factors { biometry = true; deviceLock = false }
                }
            }
        }
        // --8<-- [end:supreme-ios-configuration]
        val configuration = DSL.resolve(::IosSigningKeyConfiguration, configureKey)
        configuration.hardware.v.backing shouldBe REQUIRED
    }
    "Platform key lifecycle" {
        // --8<-- [start:supreme-ios-key]
        val alias = "signum-docs-${Random.nextLong()}"
        val provider = IosKeychainProvider
        try {
            val signer = provider.createSigningKey(alias) { hardware { backing = DISCOURAGED } }
            val loaded = provider.getSignerForKey(alias) {
                unlockPrompt { message = "Authenticate key usage"; cancelText = "Cancel" }
            }
            loaded.publicKey shouldBe signer.publicKey
            val data = "Platform signature".encodeToByteArray()
            val signature = loaded.sign(data) {
                unlockPrompt { message = "Authenticate key usage"; cancelText = "Cancel" }
            }.signature
            loaded.makeVerifier().verify(data, signature) shouldBe SignatureVerifier.Success
        } finally {
            provider.deleteSigningKey(alias)
        }
        // --8<-- [end:supreme-ios-key]
    }
}
