import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import kotlin.random.Random

@ExperimentalStdlibApi
class ProviderTest : FreeSpec({

    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }

    "AES" {
        val key = Random.Default.nextBytes(16)
        val iv = Random.Default.nextBytes(12)
        //val aad =  Random.Default.nextBytes(16)
        val plaintext = "WUMBO".encodeToByteArray()


        println("KEY: ${key.toHexString()} IV: ${iv.toHexString()}  plaintext: ${plaintext.toHexString()}")

        println( Encryptor(EncryptionAlgorithm.AES128_GCM, key, iv, null).encrypt(plaintext))
    }
})