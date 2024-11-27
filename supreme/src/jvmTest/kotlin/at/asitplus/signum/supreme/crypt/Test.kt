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
        "is just making sure" shouldNotBe "that JVM tests are indeed running"
    }

    "AES" - {
        "CBC.PLAIN" - {
            withData(
                EncryptionAlgorithm.AES_128.CBC.PLAIN,
                EncryptionAlgorithm.AES_192.CBC.PLAIN,
                EncryptionAlgorithm.AES_256.CBC.PLAIN,
            ) {

                val key = it.randomKey()
                val iv = Random.Default.nextBytes((it.ivNumBits / 8u).toInt())
                val plaintext = Random.Default.nextBytes(256)

                println("KEY: ${key.toHexString()} IV: ${iv.toHexString()}  plaintext: ${plaintext.toHexString()}")

                val ciphertext = it.encryptorFor(key, iv).getOrThrow().encrypt(plaintext).getOrThrow()


                println(ciphertext)
                ciphertext.iv shouldBe iv
                ciphertext.shouldBeInstanceOf<Ciphertext.Unauthenticated>()


                val decrypted = ciphertext.decrypt(key).getOrThrow()
                println("DECRYPTED: " + decrypted.toHexString(HexFormat.UpperCase))
                decrypted shouldBe plaintext

            }
        }
    }

    "GCM" - {
        withData(
            EncryptionAlgorithm.AES_128.GCM,
            EncryptionAlgorithm.AES_192.GCM,
            EncryptionAlgorithm.AES_256.GCM
        ) {

            val key = it.randomKey()
            val iv = Random.Default.nextBytes((it.ivNumBits / 8u).toInt())
            val aad = Random.Default.nextBytes(32)
            val plaintext = Random.Default.nextBytes(256)

            println("KEY: ${key.toHexString()} IV: ${iv.toHexString()}  plaintext: ${plaintext.toHexString()}")

            val ciphertext = it.encryptorFor(key, iv, aad).getOrThrow().encrypt(plaintext).getOrThrow()


            println(ciphertext)
            ciphertext.iv shouldBe iv
            ciphertext.shouldBeInstanceOf<Ciphertext.Authenticated>()
            ciphertext.aad shouldBe aad

            val decrypted = ciphertext.decrypt(key).getOrThrow()
            println("DECRYPTED: " + decrypted.toHexString(HexFormat.UpperCase))
            decrypted shouldBe plaintext

        }
    }
    "CBC+HMAC" - {
        withData(
            EncryptionAlgorithm.AES_128.CBC.HMAC.SHA_1,
            EncryptionAlgorithm.AES_192.CBC.HMAC.SHA_1,
            EncryptionAlgorithm.AES_256.CBC.HMAC.SHA_1,


            EncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256,
            EncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256,
            EncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256,


            EncryptionAlgorithm.AES_128.CBC.HMAC.SHA_384,
            EncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384,
            EncryptionAlgorithm.AES_256.CBC.HMAC.SHA_384,


            EncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,
            EncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512,
            EncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512,
        ) {

            val key = it.randomKey()
            val iv = Random.Default.nextBytes((it.ivNumBits / 8u).toInt())
            val aad = Random.Default.nextBytes(32)
            val plaintext = Random.Default.nextBytes(256)

            withData(
                Random.Default.nextBytes(8),
                Random.Default.nextBytes(16),
                Random.Default.nextBytes(32),
                key
            ) { macKey ->
                println("KEY: ${key.toHexString()} MACKEY: ${macKey.toHexString()} IV: ${iv.toHexString()}  plaintext: ${plaintext.toHexString()}")

                val ciphertext =
                    it.encryptorFor(key, macKey, iv, aad).getOrThrow().encrypt(plaintext)
                        .getOrThrow()


                println(ciphertext)
                ciphertext.iv shouldBe iv
                ciphertext.shouldBeInstanceOf<Ciphertext.Authenticated.WithDedicatedMac>()
                ciphertext.aad shouldBe aad

                val decrypted = ciphertext.decrypt(key, macKey).getOrThrow()
                println("DECRYPTED: " + decrypted.toHexString(HexFormat.UpperCase))
                decrypted shouldBe plaintext
            }


        }
    }
})