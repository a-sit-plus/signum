package at.asitplus.signum.supreme.os

import at.asitplus.signum.dsl.attestation
import at.asitplus.signum.dsl.hardware
import at.asitplus.signum.indispensable.sign.verifierFor
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.signature
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
        }
        val publicKey = hardwareSigner.publicKey
        publicKey.shouldBeInstanceOf<EcdsaPublicKey>()

        val plaintext = Random.nextBytes(64)
        val signature = hardwareSigner.sign(plaintext).signature

        //@formatter:off
        EcdsaAlgorithm.withSHA256.verifierFor(publicKey).verify(plaintext, signature)
        //@formatter:on

    }
}
