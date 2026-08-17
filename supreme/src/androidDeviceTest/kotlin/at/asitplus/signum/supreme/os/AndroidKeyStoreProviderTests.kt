package at.asitplus.signum.supreme.os

import android.os.Build
import android.security.keystore.KeyProperties
import at.asitplus.shouldSucceed
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.az
import io.kotest.property.arbitrary.string
import kotlin.random.Random

val AndroidKeyStoreProviderTests by matrixSuite {
    "Create attested keypair (emulator=$isEmulator)" {
        val alias = Arb.string(minSize = 32, maxSize = 32, Codepoint.az())
            .sample(RandomSource.default()).value
        val attestChallenge = Random.nextBytes(32)
        val hardwareSigner = AndroidKeyStoreProvider.createSigningKey(alias) {
            hardware {
                backing = PREFERRED
                attestation {
                    challenge = attestChallenge
                }
            }
        }.getOrThrow()
        @Suppress("DEPRECATION")
        val isSoftwareBacked = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            hardwareSigner.securityLevel == KeyProperties.SECURITY_LEVEL_SOFTWARE
        } else {
            !hardwareSigner.keyInfo.isInsideSecureHardware
        }
        isSoftwareBacked shouldBe isEmulator
        val publicKey = hardwareSigner.publicKey
        publicKey.shouldBeInstanceOf<CryptoPublicKey.EC>()

        val plaintext = Random.nextBytes(64)
        val signature = hardwareSigner.sign(plaintext).signature

        //@formatter:off
        SignatureAlgorithm.ECDSAwithSHA256.verifierFor(publicKey).transform {
            it.verify(plaintext, signature) }.shouldSucceed()
        //@formatter:on

    }
}
