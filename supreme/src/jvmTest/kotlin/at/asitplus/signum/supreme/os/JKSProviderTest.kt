package at.asitplus.signum.supreme.os

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.supreme.sign.SigningKeyConfiguration
import at.asitplus.signum.supreme.sign.makeVerifier
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.signature
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.should
import io.kotest.matchers.shouldNot
import io.kotest.property.azstring
import java.nio.file.Files
import kotlin.random.Random

class JKSProviderTest : FreeSpec({
    "Ephemeral" - {

        "EC" {
            val ks = JKSProvider.Ephemeral().getOrThrow()
            val alias = "Elfenbeinschloss"
            ks.getSignerForKey(alias) shouldNot succeed
            val signer = ks.createSigningKey(alias).getOrThrow()
            val otherSigner = ks.getSignerForKey(alias).getOrThrow()

            val data = Random.Default.nextBytes(64)
            val signature = signer.sign(data).signature
            otherSigner.makeVerifier().getOrThrow().verify(data, signature) should succeed
        }

        "RSA" {
            repeat(500) {
                val ks = JKSProvider.Ephemeral().getOrThrow()
                val alias = "Elfenbeinschloss"
                ks.getSignerForKey(alias) shouldNot succeed
                val signer = ks.createSigningKey(alias) {
                    rsa {
                        bits = 1024 //faster testing
                        paddings = setOf(RSAPadding.PKCS1)
                        digests = setOf(Digest.SHA256)
                        publicExponent = SigningKeyConfiguration.RSAConfiguration.F4
                    }
                }.getOrThrow()
                val otherSigner = ks.getSignerForKey(alias).getOrThrow()

                val data = Random.Default.nextBytes(64)
                val signature = signer.sign(data).signature
                otherSigner.makeVerifier().getOrThrow().verify(data, signature) should succeed
            }
        }
    }
    "File-based persistence" {
        val tempfile = Files.createTempFile(Random.azstring(16), null).also { Files.delete(it) }
        try {
            val alias = "Elfenbeinturm"
            val correctPassword = "Schwertfischfilet".toCharArray()
            val wrongPassword = "Bartfischfilet".toCharArray()

            val ks1 = JKSProvider {
                file {
                    file = tempfile
                    password = correctPassword
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

            JKSProvider {
                file {
                    file = tempfile
                    password = wrongPassword
                }
            }.getOrThrow().let {
                // wrong password should fail
                it.getSignerForKey(alias) shouldNot succeed
            }

            JKSProvider {
                file {
                    file = tempfile
                    password = correctPassword
                }
            }.getOrThrow().let {
                it.getSignerForKey(alias) should succeed
                it.deleteSigningKey(alias)
            }

            // check that ks1 "sees" the deletion that was made by ks3
            ks1.getSignerForKey(alias) shouldNot succeed
        } finally {
            Files.deleteIfExists(tempfile)
        }
    }
})
