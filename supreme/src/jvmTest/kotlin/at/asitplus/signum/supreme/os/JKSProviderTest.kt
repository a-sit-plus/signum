package at.asitplus.signum.supreme.os

import at.asitplus.signum.supreme.sign.makeVerifier
import at.asitplus.signum.supreme.sign.sign
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.property.azstring
import java.nio.file.Files
import kotlin.random.Random

class JKSProviderTest : FreeSpec({
    "Ephemeral" {
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
    "File-based persistence" {
        val tempfile = Files.createTempFile(Random.azstring(16),null).also { Files.delete(it) }
        try {
            val alias = "Elfenbeinturm"

            val ks1 = SigningProvider {
                keystoreFile {
                    file = tempfile
                    password = "Schwertfischfilet".toCharArray()
                }
            }.getOrThrow().also {
                it.getSignerForKey(alias) shouldNot succeed
                it.createSigningKey(alias) should succeed
                it.createSigningKey(alias) shouldNot succeed
                it.getSignerForKey(alias) should succeed
                it.deleteSigningKey(alias)
                it.getSignerForKey(alias) shouldNot succeed
                it.createSigningKey(alias) should succeed
            }

            SigningProvider {
                keystoreFile {
                    file = tempfile
                    password = "Bartfischfilet".toCharArray()
                }
            }.getOrThrow().let {
                // wrong password should fail
                it.getSignerForKey(alias) shouldNot succeed
            }

            SigningProvider {
                keystoreFile {
                    file = tempfile
                    password = "Schwertfischfilet".toCharArray()
                }
            }.getOrThrow().let {
                it.getSignerForKey(alias) should succeed
                it.deleteSigningKey(alias)
            }

            ks1.getSignerForKey(alias) shouldNot succeed
        } finally { Files.deleteIfExists(tempfile) }
    }
})