package at.asitplus.signum.supreme.sign

import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.should
import kotlin.random.Random

class EphemeralSignerCommonTests : FreeSpec({
    "RSA".config(invocations = 5) {
        val signer = Signer { rsa {} }
        val data = Random.Default.nextBytes(64)
        val signature = signer.sign(data).getOrThrow()

        val verifier = signer.makeVerifier().getOrThrow()
        verifier.verify(data, signature) should succeed
    }
    "ECDSA".config(invocations = 5) {
        val signer = Signer { ec {} }
        val data = Random.Default.nextBytes(64)
        val signature = signer.sign(data).getOrThrow()

        val verifier = signer.makeVerifier().getOrThrow()
        verifier.verify(data, signature) should succeed
    }
})
