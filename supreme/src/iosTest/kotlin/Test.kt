import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.crypt.CBC
import at.asitplus.signum.supreme.crypt.decrypt
import at.asitplus.signum.supreme.crypt.encryptorFor
import at.asitplus.signum.supreme.crypt.randomKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt
import kotlin.random.Random

@ExperimentalStdlibApi
class ProviderTest : FreeSpec({

    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }

    "AES" - {
        "GCM" - {
            withData(EncryptionAlgorithm.AES128_GCM, EncryptionAlgorithm.AES192_GCM, EncryptionAlgorithm.AES256_GCM) {

                val key = it.randomKey()
                val iv = Random.Default.nextBytes((it.ivNumBits / 8u).toInt())
                val aad = Random.Default.nextBytes(32)
                val plaintext = Random.Default.nextBytes(256)


                println("KEY: ${key.toHexString()} IV: ${iv.toHexString()}  plaintext: ${plaintext.toHexString()}")

                val ciphertext: Ciphertext.Authenticated =
                    it.encryptorFor(key, iv, aad).getOrThrow().encrypt(plaintext).getOrThrow()
                println(ciphertext)
                ciphertext.iv shouldBe iv
                ciphertext.aad shouldBe aad

                val decrypted = ciphertext.decrypt(key).getOrThrow()
                println(
                    "DECRYPTED: " + decrypted.toHexString(HexFormat.UpperCase)
                )
                decrypted shouldBe plaintext

            }
        }

        "CBC" {
            val plaintext = Random.Default.nextBytes(256)
            val randomKey = EncryptionAlgorithm.AES128_CBC_HMAC256.randomKey()
            val iv = Random.Default.nextBytes(16)
            println("KEY: ${randomKey.toHexString()} IV: ${iv.toHexString()}  plaintext: ${plaintext.toHexString()}")
            val ciphertext= CBC(kCCEncrypt, randomKey,iv,plaintext)
            println("CRYPT: ${ciphertext.toHexString()}")

            val decrypted = CBC(kCCDecrypt, randomKey,iv, ciphertext)

            println("DECRYPTED: " + decrypted.toHexString())

            decrypted shouldBe plaintext
        }
    }
})