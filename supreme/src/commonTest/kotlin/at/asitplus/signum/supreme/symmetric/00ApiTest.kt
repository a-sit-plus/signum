package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.InsecureRandom
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking
import kotlin.random.Random

@OptIn(HazardousMaterials::class)
val ApiTest  by matrixSuite {

    "Decrypt with AAD" {
        val gcmKey = SymmetricEncryptionAlgorithm.AES_128.GCM.randomKey()
        val hmacKey = SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256.randomKey()
        val plaintext = byteArrayOf(1)
        val aad = byteArrayOf(2)
        val gcmBox = gcmKey.encrypt(plaintext, aad)
        val hmacBox = hmacKey.encrypt(plaintext, aad)

        gcmBox.decrypt(gcmKey, aad) shouldBe plaintext
        hmacBox.decrypt(hmacKey, aad) shouldBe plaintext
        shouldThrow<IllegalArgumentException> { gcmBox.decrypt(hmacKey) }
        shouldThrow<IllegalArgumentException> { hmacBox.decrypt(gcmKey) }

        // expected compile error. do not change comment or the line below
        // gcmBox.decrypt(hmacKey, aad)
        // expected compile error. do not change comment or the line below
        // hmacBox.decrypt(gcmKey, aad)
    }

    "Utterly Untyped v2" - {
        data(
            sequenceOf(
                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,
                SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_128.GCM,
                SymmetricEncryptionAlgorithm.AES_128.ECB,
                SymmetricEncryptionAlgorithm.ChaCha20Poly1305
            ).map { runBlocking {
                val key = it.randomKey(InsecureRandom)
                val plain = Random.nextBytes(131)
                val encrypted = key.encrypt(plain)
                Triple(key, plain, encrypted)
            } }
        ) test { (key, plain, encrypted) ->
            encrypted.decrypt(key) shouldBe plain
        }
    }

    "Utterly Untyped" - {
        listOf(SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512, SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN, SymmetricEncryptionAlgorithm.AES_128.GCM, SymmetricEncryptionAlgorithm.AES_128.ECB, SymmetricEncryptionAlgorithm.ChaCha20Poly1305).asData() test { algorithm ->

            //create a key, encrypt and decrypt works!
            val key = algorithm.randomKey(InsecureRandom)
            val plain = "Harvest".encodeToByteArray()
            val box = key.encrypt(plain)
            box.decrypt(key) shouldBe plain


            //if you load a key, you are forced to know whether a dedicated MAC key is required
            val loadedKey = when (algorithm.hasDedicatedMac()) {
                true -> {
                    algorithm.keyFrom(Random.nextBytes(algorithm.keySize.bytes.toInt()), Random.nextBytes(32))
                    // expected compile error. do not change comment or the line below
                    //algorithm.keyFrom(byteArrayOf())
                }

                false -> {
                    algorithm.keyFrom(Random.nextBytes(algorithm.keySize.bytes.toInt()))
                    // expected compile error. do not change comment or the line below
                    //algorithm.keyFrom(byteArrayOf(),byteArrayOf())
                }
            }


            //creating sealed boxes
            when (algorithm.requiresNonce()) {
                true -> when (algorithm.isAuthenticated()) {
                    true -> {
                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())


                    }

                    false -> {
                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())

                    }
                }

                false -> when (algorithm.isAuthenticated()) {
                    true -> {
                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf())

                        algorithm.sealedBox.from(byteArrayOf(), ByteArray(algorithm.authTagSize.bytes.toInt()))

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())
                    }

                    false -> {
                        algorithm.sealedBox.from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf(),byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())
                    }
                }
            }


            //creating sealed boxes
            when (algorithm.isAuthenticated()) {
                true -> when (algorithm.requiresNonce()) {
                    true -> {
                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())
                    }

                    false -> {
                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf())

                        algorithm.sealedBox.from(byteArrayOf(), ByteArray(algorithm.authTagSize.bytes.toInt()))

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())


                    }
                }

                false -> when (algorithm.requiresNonce()) {
                    true -> {
                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())

                    }

                    false -> {
                        algorithm.sealedBox.from(byteArrayOf())
                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.from(byteArrayOf(),byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // expected compile error. do not change comment or the line below
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())

                    }
                }
            }
        }
    }

    "Authenticated" - {
        listOf(SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512, SymmetricEncryptionAlgorithm.AES_128.GCM, SymmetricEncryptionAlgorithm.ChaCha20Poly1305).asData() test {

            val algorithm = it

            //create a key, encrypt and decrypt works!
            val key = algorithm.randomKey(InsecureRandom)
            val plain = "Harvest".encodeToByteArray()
            val box = key.encrypt(plain)
            box.decrypt(key) shouldBe plain


            //if you load a key, you are forced to know whether a dedicated MAC key is required
            val loadedKey = when (algorithm.hasDedicatedMac()) {
                true -> {
                    algorithm.keyFrom(Random.nextBytes(algorithm.keySize.bytes.toInt()), Random.nextBytes(32))
                    // expected compile error. do not change comment or the line below
                    //algorithm.keyFrom(byteArrayOf())
                }

                false -> {
                    algorithm.keyFrom(Random.nextBytes(algorithm.keySize.bytes.toInt()))
                    // expected compile error. do not change comment or the line below
                    //algorithm.keyFrom(byteArrayOf(),byteArrayOf())
                }
            }
            // expected compile error. do not change comment or the line below
            // algorithm.sealedBox.from(byteArrayOf())

            // expected compile error. do not change comment or the line below
            // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

            // expected compile error. do not change comment or the line below
            // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

            //correct
            algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())


        }
    }

}
