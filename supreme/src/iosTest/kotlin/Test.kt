import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.crypt.decrypt
import at.asitplus.signum.supreme.crypt.encryptorFor
import at.asitplus.signum.supreme.crypt.randomKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

@ExperimentalStdlibApi
class ProviderTest : FreeSpec({

    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }

    "AES" - {
        "GCM + CBC.PLAIN" - {
            withData(
                EncryptionAlgorithm.AES_128.GCM,
                EncryptionAlgorithm.AES_192.GCM,
                EncryptionAlgorithm.AES_256.GCM,
                EncryptionAlgorithm.AES_128.CBC.PLAIN,
                EncryptionAlgorithm.AES_192.CBC.PLAIN,
                EncryptionAlgorithm.AES_256.CBC.PLAIN,
            ) {

                val key = it.randomKey()
                val iv = Random.Default.nextBytes((it.ivNumBits / 8u).toInt())
                val aad = Random.Default.nextBytes(32)
                val plaintext = Random.Default.nextBytes(256)


                //  println("KEY: ${key.toHexString()} IV: ${iv.toHexString()}  plaintext: ${plaintext.toHexString()}")

                val ciphertext: Ciphertext<*> =
                    when (it) {
                        is EncryptionAlgorithm.Authenticated -> it.encryptorFor(key, iv, aad).getOrThrow()
                            .encrypt(plaintext).getOrThrow()

                        is EncryptionAlgorithm.Unauthenticated -> it.encryptorFor(key, iv).getOrThrow().encrypt(plaintext)
                            .getOrThrow()

                        else -> TODO()
                    }

              //  println(ciphertext)
                ciphertext.iv shouldBe iv
                if (it is EncryptionAlgorithm.Authenticated) {
                    ciphertext.shouldBeInstanceOf<Ciphertext.Authenticated>()
                    ciphertext.aad shouldBe aad
                }

                val decrypted = ciphertext.decrypt(key).getOrThrow()
              //  println("DECRYPTED: " + decrypted.toHexString(HexFormat.UpperCase))
                decrypted shouldBe plaintext

            }
        }
    }
})