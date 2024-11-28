import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.crypt.decrypt
import at.asitplus.signum.supreme.crypt.encryptorFor
import at.asitplus.signum.supreme.crypt.randomKey
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

@ExperimentalStdlibApi
class AESTest : FreeSpec({

    "AES" - {
        "CBC.PLAIN" - {
            withData(
                EncryptionAlgorithm.AES_128.CBC.PLAIN,
                EncryptionAlgorithm.AES_192.CBC.PLAIN,
                EncryptionAlgorithm.AES_256.CBC.PLAIN,
            ) {

                val key = it.randomKey()
                val plaintext = Random.Default.nextBytes(256)

                withData(
                    nameFn = { "IV: " + it?.toHexString() },
                    Random.Default.nextBytes((it.ivNumBits / 8u).toInt()),
                    null
                ) { iv ->


                    println("KEY: ${key.toHexString()} IV: ${iv?.toHexString()}  plaintext: ${plaintext.toHexString()}")

                    val ciphertext = it.encryptorFor(key, iv).getOrThrow().encrypt(plaintext).getOrThrow()


                    println(ciphertext)
                    ciphertext.iv.shouldNotBeNull()
                    ciphertext.iv!!.size * 8 shouldBe it.ivNumBits.toInt()
                    iv?.let { ciphertext.iv shouldBe it }
                    ciphertext.shouldBeInstanceOf<Ciphertext.Unauthenticated>()


                    val decrypted = ciphertext.decrypt(key).getOrThrow()
                    println("DECRYPTED: " + decrypted.toHexString(HexFormat.UpperCase))
                    decrypted shouldBe plaintext

                    val wrongDecrypted = ciphertext.decrypt(ciphertext.algorithm.randomKey())
                    wrongDecrypted shouldNot succeed

                    val wrongCiphertext = Ciphertext.Unauthenticated(ciphertext.algorithm, Random.Default.nextBytes(ciphertext.encryptedData.size), iv= ciphertext.iv)

                    val wrongWrongDecrypted= wrongCiphertext.decrypt(ciphertext.algorithm.randomKey())
                    wrongWrongDecrypted shouldNot succeed

                    val wrongRightDecrypted = wrongCiphertext.decrypt(key)
                    wrongRightDecrypted shouldNot succeed

                }
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
            val plaintext = Random.Default.nextBytes(256)
            withData(
                nameFn = { "IV: " + it?.toHexString() },
                Random.Default.nextBytes((it.ivNumBits / 8u).toInt()),
                null
            ) { iv ->

                withData(nameFn = { "AAD: " + it?.toHexString() }, Random.Default.nextBytes(32), null) { aad ->
                    println("KEY: ${key.toHexString()} IV: ${iv?.toHexString()}  plaintext: ${plaintext.toHexString()}")

                    val ciphertext = it.encryptorFor(key, iv, aad).getOrThrow().encrypt(plaintext).getOrThrow()


                    println(ciphertext)
                    ciphertext.iv.shouldNotBeNull()
                    ciphertext.iv!!.size * 8 shouldBe it.ivNumBits.toInt()

                    iv?.let { ciphertext.iv shouldBe it }
                    ciphertext.shouldBeInstanceOf<Ciphertext.Authenticated>()
                    ciphertext.aad shouldBe aad

                    val decrypted = ciphertext.decrypt(key).getOrThrow()
                    println("DECRYPTED: " + decrypted.toHexString(HexFormat.UpperCase))
                    decrypted shouldBe plaintext
                }
            }
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
            val plaintext = Random.Default.nextBytes(256)

            withData(
                nameFn = { "MAC KEY " + it.toHexString() },
                Random.Default.nextBytes(8),
                Random.Default.nextBytes(16),
                Random.Default.nextBytes(32),
                key
            ) { macKey ->

                withData(
                    nameFn = { "IV: " + it?.toHexString() },
                    Random.Default.nextBytes((it.ivNumBits / 8u).toInt()),
                    null
                ) { iv ->
                    withData(nameFn = { "AAD: " + it?.toHexString() }, Random.Default.nextBytes(32), null) { aad ->
                        println("KEY: ${key.toHexString()} MACKEY: ${macKey.toHexString()} IV: ${iv?.toHexString()}  plaintext: ${plaintext.toHexString()}")
                        val ciphertext =
                            it.encryptorFor(key, macKey, iv, aad).getOrThrow().encrypt(plaintext)
                                .getOrThrow()


                        println(ciphertext)
                        iv?.let { ciphertext.iv shouldBe it }
                        ciphertext.iv.shouldNotBeNull()
                        ciphertext.shouldBeInstanceOf<Ciphertext.Authenticated.WithDedicatedMac>()
                        ciphertext.aad shouldBe aad

                        val decrypted = ciphertext.decrypt(key, macKey).getOrThrow()
                        println("DECRYPTED: " + decrypted.toHexString(HexFormat.UpperCase))
                        decrypted shouldBe plaintext
                    }

                }
            }
        }
    }
})