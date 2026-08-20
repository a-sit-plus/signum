package at.asitplus.signum.supreme.os

import at.asitplus.shouldSucceed
import at.asitplus.signum.dsl.attestation
import at.asitplus.signum.dsl.hardware
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.integrity.verifierFor
import at.asitplus.signum.indispensable.integrity.verify
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.az
import io.kotest.property.arbitrary.string
import kotlin.random.Random

val AndroidKeyStoreProviderTests by matrixSuite {
    "Create attested keypair" {
        val alias = Arb.string(minSize = 32, maxSize = 32, Codepoint.az())
            .sample(RandomSource.default()).value
        val attestChallenge = Random.nextBytes(32)
        val hardwareSigner = AndroidKeyStoreProvider.createSigningKey(alias) {
            hardware {
                attestation {
                    challenge = attestChallenge
                }
            }
        }.getOrThrow()
        val publicKey = hardwareSigner.publicKey
        publicKey.shouldBeInstanceOf<CryptoPublicKey.EC>()

        val plaintext = Random.nextBytes(64)
        val signature = hardwareSigner.sign(plaintext).signature

        //@formatter:off
        ECDSAAlgorithm.withSHA256.verifierFor(publicKey).verify(plaintext, signature).shouldSucceed()
        //@formatter:on

    }
}
