package at.asitplus.signum.supreme.os

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.sign.sign
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import br.com.colman.kotest.FreeSpec
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.azstring
import kotlin.random.Random

class AndroidKeyStoreProviderTests: FreeSpec({
    "Create attested keypair" {
        val alias = Random.azstring(32)
        val attestChallenge = Random.nextBytes(32)
        val hardwareSigner = AndroidKeyStoreProvider().createSigningKey(alias) {
            hardware {
                attestation {
                    challenge = attestChallenge
                }
            }
        }.getOrThrow()
        val publicKey = hardwareSigner.publicKey
        publicKey.shouldBeInstanceOf<CryptoPublicKey.EC>()

        val plaintext = Random.nextBytes(64)
        val signature = hardwareSigner.sign(plaintext).getOrThrow()

        SignatureAlgorithm.ECDSAwithSHA256.verifierFor(publicKey).getOrThrow()
            .verify(plaintext, signature).getOrThrow()

       // val certificateChain = hardwareSigner.certificateChain
        // TODO verify attestation
    }
})