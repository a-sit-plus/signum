package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe

@OptIn(HazardousMaterials::class)
class `00ApiTest` : FreeSpec({

    "Utterly Untyped" - {
        withData(
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,
            SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_128.GCM,
            SymmetricEncryptionAlgorithm.AES_128.ECB,
            SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        ) {

            val algorithm = it// as SymmetricEncryptionAlgorithm<*, *, *>

            //create a key, encrypt and decrypt works!
            val key = algorithm.randomKey()
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
                        algorithm
                        //compile error
                        //algorithm.sealedBox(byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(),byteArrayOf())
                        algorithm.sealedBoxFrom(
                            byteArrayOf(), //nonce
                            byteArrayOf(), //encrypted
                            byteArrayOf(), //nonce
                        )
                        algorithm.sealedBoxFrom(
                            byteArrayOf(),
                            byteArrayOf(),
                            byteArrayOf(),
                            byteArrayOf(),
                        )
                    }

                    false -> {
                        //Compile error
                        //algorithm.sealedBox(byteArrayOf())
                        algorithm.sealedBoxFrom(byteArrayOf(), byteArrayOf())
                        //Compile error
                        //algorithm.sealedBox(byteArrayOf(), byteArrayOf(),byteArrayOf())
                        //Compile error
                        //algorithm.sealedBox(byteArrayOf(), byteArrayOf(),byteArrayOf(), byteArrayOf())


                    }
                }

                false -> when (algorithm.isAuthenticated()) {
                    true -> {
                        //compile error
                        //algorithm.sealedBox(byteArrayOf())
                        algorithm.sealedBoxFrom(byteArrayOf(), byteArrayOf())
                        //why ambiguous??
                        algorithm.sealedBoxFrom(byteArrayOf(), byteArrayOf(), byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(), byteArrayOf(), byteArrayOf(), byteArrayOf())
                    }

                    false -> {
                        algorithm.sealedBoxFrom(byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(),byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(),byteArrayOf(),byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(),byteArrayOf(),byteArrayOf())
                    }
                }
            }


            //creating sealed boxes
            when (algorithm.isAuthenticated()) {
                true -> when (algorithm.requiresNonce()) {
                    true -> {
                        algorithm
                        //compile error
                        //algorithm.sealedBox(byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(),byteArrayOf())
                        //why ambiguous?
                        algorithm.sealedBoxFrom(
                            byteArrayOf(), //nonce
                            byteArrayOf(), //encrypted
                            byteArrayOf(), //nonce
                        )
                        algorithm.sealedBoxFrom(
                            byteArrayOf(), //nonce
                            byteArrayOf(), //nonce
                            byteArrayOf(), //nonce
                            byteArrayOf(), //nonce
                        )
                    }

                    false -> {
                        //Compile error
                        //algorithm.sealedBox(byteArrayOf())
                        algorithm.sealedBoxFrom(byteArrayOf(), byteArrayOf())
                        algorithm.sealedBoxFrom(byteArrayOf(), byteArrayOf(), byteArrayOf())
                        //Compile error
                        //algorithm.sealedBox(byteArrayOf(), byteArrayOf(),byteArrayOf(), byteArrayOf())


                    }
                }

                false -> when (algorithm.requiresNonce()) {
                    true -> {
                        //compile error
                        //algorithm.sealedBox(byteArrayOf())
                        algorithm.sealedBoxFrom(byteArrayOf(), byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(), byteArrayOf(), byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(), byteArrayOf(), byteArrayOf(), byteArrayOf())
                    }

                    false -> {
                        algorithm.sealedBoxFrom(byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(),byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(),byteArrayOf(),byteArrayOf())
                        //compile error
                        //algorithm.sealedBox(byteArrayOf(),byteArrayOf(),byteArrayOf())
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
                val key = algorithm.randomKey()
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
                //compile error
                //algorithm.sealedBox(byteArrayOf(), byteArrayOf())

                //correct
                algorithm.sealedBoxFrom(byteArrayOf(), byteArrayOf(), byteArrayOf())

                //correct
                algorithm.sealedBoxFrom(byteArrayOf(), byteArrayOf(), byteArrayOf(), byteArrayOf())

        }
    }

})