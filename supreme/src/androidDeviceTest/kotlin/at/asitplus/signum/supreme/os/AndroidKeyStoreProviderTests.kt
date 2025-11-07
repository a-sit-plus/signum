package at.asitplus.signum.supreme.os

import at.asitplus.shouldSucceed
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.az
import io.kotest.property.arbitrary.string
import kotlin.random.Random

val AndroidKeyStoreProviderTests by testSuite {
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
        SignatureAlgorithm.ECDSAwithSHA256.verifierFor(publicKey).transform {
            it.verify(plaintext, signature) }.shouldSucceed()
        //@formatter:on

    }
}
