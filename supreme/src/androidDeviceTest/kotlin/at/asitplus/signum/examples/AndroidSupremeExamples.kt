package at.asitplus.signum.examples

import at.asitplus.signum.dsl.*
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.os.AndroidKeyStoreProvider
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.seconds
import kotlin.random.Random

val AndroidSupremeExamples by matrixSuite {
    "Platform configuration" {
        // --8<-- [start:supreme-android-configuration]
        val serverChallenge = ByteArray(32) { it.toByte() } // fixed test fixture; obtain a fresh challenge from your server!
        val configureKey: AndroidSigningKeyConfiguration.() -> Unit = {
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
        // --8<-- [end:supreme-android-configuration]
        val configuration = DSL.resolve(::AndroidSigningKeyConfiguration, configureKey)
        configuration.hardware.v!!.backing shouldBe REQUIRED
    }
    "Platform key lifecycle" {
        // --8<-- [start:supreme-android-key]
        val alias = "signum-docs-${Random.nextLong()}"
        val provider = AndroidKeyStoreProvider
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
        // --8<-- [end:supreme-android-key]
    }
}
