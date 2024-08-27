package at.asitplus.signum.supreme.os

import at.asitplus.signum.supreme.sign.makeVerifier
import at.asitplus.signum.supreme.sign.sign
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import kotlin.random.Random

class JKSProviderTest : FreeSpec({
    "create - get - delete" {
        val ks = JKSProvider.Ephemeral()
        val alias = "Elfenbeinschloss"
        ks.getSignerForKey(alias) shouldNot succeed
        val signer = ks.createSigningKey(alias).getOrThrow()
        val otherSigner = ks.getSignerForKey(alias).getOrThrow()
        otherSigner.attestation shouldBe signer.attestation

        val data = Random.Default.nextBytes(64)
        val signature = signer.sign(data).getOrThrow()
        otherSigner.makeVerifier().getOrThrow().verify(data, signature) should succeed
    }
})
