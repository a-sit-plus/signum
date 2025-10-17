package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.InsecureRandom
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import at.asitplus.testballoon.checkAllTests
import at.asitplus.testballoon.checkAllSuites
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.testScope
import kotlin.time.Duration.Companion.minutes

@OptIn(HazardousMaterials::class)
val ApiTest  by testSuite() {

    "Utterly Untyped v2" - {
        withData(
            sequenceOf(
                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,
                SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_128.GCM,
                SymmetricEncryptionAlgorithm.AES_128.ECB,
                SymmetricEncryptionAlgorithm.ChaCha20Poly1305
            ).map { runBlocking {
                val key = it.randomKey(InsecureRandom)
                val plain = Random.nextBytes(131)
                val encrypted = key.encrypt(plain).getOrThrow()
                Triple(key, plain, encrypted)
            } }
        ) { (key, plain, encrypted) ->
            encrypted.decrypt(key).let {
                it should succeed
                it.getOrThrow() shouldBe plain
            }
        }
    }

    "Utterly Untyped" - {
        withData(
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,
            SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_128.GCM,
            SymmetricEncryptionAlgorithm.AES_128.ECB,
            SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        ) { algorithm ->

            //create a key, encrypt and decrypt works!
            val key = algorithm.randomKey(InsecureRandom)
            val plain = "Harvest".encodeToByteArray()
            val box = key.encrypt(plain).getOrThrow()
            box.decrypt(key).onSuccess { it shouldBe plain } should succeed


            //if you load a key, you are forced to know whether a dedicated MAC key is required
            val loadedKey = when (algorithm.hasDedicatedMac()) {
                true -> {
                    algorithm.keyFrom(byteArrayOf(), byteArrayOf())
                    //Compile error
                    //algorithm.keyFrom(byteArrayOf())
                }

                false -> {
                    algorithm.keyFrom(byteArrayOf())
                    //Compile error
                    //algorithm.keyFrom(byteArrayOf(),byteArrayOf())
                }
            }


            //creating sealed boxes
            when (algorithm.requiresNonce()) {
                true -> when (algorithm.isAuthenticated()) {
                    true -> {
                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())


                    }

                    false -> {
                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())

                    }
                }

                false -> when (algorithm.isAuthenticated()) {
                    true -> {
                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf())

                        algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        //compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())
                    }

                    false -> {
                        algorithm.sealedBox.from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf(),byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())
                    }
                }
            }


            //creating sealed boxes
            when (algorithm.isAuthenticated()) {
                true -> when (algorithm.requiresNonce()) {
                    true -> {
                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())
                    }

                    false -> {
                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf())

                        algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        //compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())


                    }
                }

                false -> when (algorithm.requiresNonce()) {
                    true -> {
                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

                        algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())

                    }

                    false -> {
                        algorithm.sealedBox.from(byteArrayOf())
                        // compile error
                        // algorithm.sealedBox.from(byteArrayOf(),byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

                        // compile error
                        // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())

                    }
                }
            }
        }
    }

    "Authenticated" - {
        withData(
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,
            SymmetricEncryptionAlgorithm.AES_128.GCM,
            SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        ) {

            val algorithm = it

            //create a key, encrypt and decrypt works!
            val key = algorithm.randomKey(InsecureRandom)
            val box = key.encrypt("Harvest".encodeToByteArray()).getOrThrow()
            box.decrypt(key) should succeed


            //if you load a key, you are forced to know whether a dedicated MAC key is required
            val loadedKey = when (algorithm.hasDedicatedMac()) {
                true -> {
                    algorithm.keyFrom(byteArrayOf(), byteArrayOf())
                    //Compile error
                    //algorithm.keyFrom(byteArrayOf())
                }

                false -> {
                    algorithm.keyFrom(byteArrayOf())
                    //Compile error
                    //algorithm.keyFrom(byteArrayOf(),byteArrayOf())
                }
            }
            // compile error
            // algorithm.sealedBox.from(byteArrayOf())

            // compile error
            // algorithm.sealedBox.from(byteArrayOf(), byteArrayOf())

            // compile error
            // algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf())

            //correct
            algorithm.sealedBox.withNonce(byteArrayOf()).from(byteArrayOf(), byteArrayOf())


        }
    }

}