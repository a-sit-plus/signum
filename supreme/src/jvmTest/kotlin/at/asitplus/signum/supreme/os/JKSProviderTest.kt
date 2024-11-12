package at.asitplus.signum.supreme.os

import at.asitplus.signum.supreme.sign.makeVerifier
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.signature
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.property.azstring
import java.nio.file.Files
import java.nio.file.Path
import kotlin.random.Random

@OptIn(ExperimentalStdlibApi::class)
class JKSProviderTest : FreeSpec({
    "Ephemeral" {
        val ks = JKSProvider.Ephemeral().getOrThrow()
        val alias = "Elfenbeinschloss"
        ks.getSignerForKey(alias) shouldNot succeed
        val signer = ks.createSigningKey(alias).getOrThrow()
        val otherSigner = ks.getSignerForKey(alias).getOrThrow()

        val data = Random.Default.nextBytes(64)
        val signature = signer.sign(data).signature
        otherSigner.makeVerifier().getOrThrow().verify(data, signature) should succeed
    }
    "Key With Password" {
        val ks = JKSProvider {
            file {
                file = Path.of("src/jvmTest/resources/DoorsOfDurin.p12")
                password = "password".toCharArray()

                /* test auto-detection */
                storeType shouldBe "pkcs12"
            }
        }.getOrThrow()
        val alias = "Moria"
        val correctKeyPassword = "Mellon".toCharArray()
        val wrongKeyPassword = "Edro".toCharArray()
        ks.getSignerForKey(alias) shouldNot succeed
        ks.getSignerForKey(alias) { privateKeyPassword = wrongKeyPassword } shouldNot succeed
        val signer = ks.getSignerForKey(alias) { privateKeyPassword = correctKeyPassword }.getOrThrow()
        signer.publicKey.encodeToDer().toHexString(HexFormat.UpperCase) shouldBe
                "3059301306072A8648CE3D020106082A8648CE3D030107034200046EEDD7DCE99AA264797906CE55BC158E4" +
                "22EA9722E7EB0F0A6C7C9AB53F4B0D09176D8D169F52872BE2ED31D33C9ABD5785BB1DF96F53213BA659636" +
                "96527B09"
    }
    "File-based persistence" {
        val tempfile = Files.createTempFile(Random.azstring(16),null).also { Files.delete(it) }
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
        } finally { Files.deleteIfExists(tempfile) }
    }
})
