@file:OptIn(SecretExposure::class)

package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.InsecureRandom
import at.asitplus.signum.supreme.succeed
import at.asitplus.signum.supreme.symmetric.discouraged.andPredefinedNonce
import at.asitplus.signum.supreme.symmetric.discouraged.encrypt
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.withClue
import io.kotest.engine.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.random.nextUInt
import kotlin.time.Clock
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.testScope
import kotlin.time.Duration.Companion.minutes

@OptIn(HazardousMaterials::class)
val SymmetricTest by testSuite {

    "README" {

        //base case
        val secret = "Top Secret".encodeToByteArray()
        val authenticatedData = "Bottom Secret".encodeToByteArray()
        val secretKey = SymmetricEncryptionAlgorithm.ChaCha20Poly1305.randomKey(InsecureRandom)
        val encrypted = secretKey.encrypt(secret, authenticatedData).getOrThrow(/*handle error*/)
        encrypted.decrypt(secretKey, authenticatedData).getOrThrow(/*handle error*/) shouldBe secret

        //getting data from external

        val algo = SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        val nonce = encrypted.nonce
        val ciphertext = encrypted.encryptedData
        val authTag = encrypted.authTag
        val externalAAD = authenticatedData
        val keyBytes = secretKey.secretKey.getOrThrow()

        val preSharedKey = algo.keyFrom(keyBytes).getOrThrow()

        val box = algo.sealedBox.withNonce(nonce).from(ciphertext, authTag).getOrThrow(/*handle error*/)
        box.decrypt(preSharedKey, /*also pass AAD*/ externalAAD).getOrThrow(/*handle error*/) shouldBe secret

        //direct decryption
        preSharedKey.decrypt(nonce, ciphertext, authTag, externalAAD).getOrThrow(/*handle error*/) shouldBe secret

        val payload = "More matter, with less art!".encodeToByteArray()

        //define algorithm parameters
        val algorithm = SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512
            //with a custom HMAC input calculation function
            .Custom(32.bytes) { ciphertext, iv, aad -> //A shorter version of RFC 7518
                aad + iv + ciphertext + aad.size.encodeTo4Bytes()
            }

        //any size is fine, really. omitting the override generates a mac key of the same size as the encryption key
        val key = algorithm.randomKey(macKeyLength = 32.bit, InsecureRandom)
        val aad = Clock.System.now().toString().encodeToByteArray()

        val sealedBox = key.encrypt(
            payload,
            authenticatedData = aad,
        ).getOrThrow(/*handle error*/)

        //because everything is structured, decryption is simple
        val recovered = sealedBox.decrypt(key, aad).getOrThrow(/*handle error*/)

        recovered shouldBe payload //success!

        //we can also manually construct the sealed box, if we know the algorithm:
        val reconstructed = algorithm.sealedBox.withNonce(sealedBox.nonce).from(
            encryptedData = sealedBox.encryptedData, /*Could also access authenticatedCipherText*/
            authTag = sealedBox.authTag,
        ).getOrThrow()

        val manuallyRecovered = reconstructed.decrypt(
            key,
            authenticatedData = aad,
        ).getOrThrow(/*handle error*/)

        manuallyRecovered shouldBe payload //great success!

        //if we just know algorithm and key bytes, we can also construct a symmetric key
        reconstructed.decrypt(
            algorithm.keyFrom(key.encryptionKey.getOrThrow(), key.macKey.getOrThrow()).getOrThrow(/*handle error*/),
            aad
        ).getOrThrow(/*handle error*/) shouldBe payload //greatest success!
    }


    "Illegal IV Size" - {
        withDataSuites(
            SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN,

            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_1,
            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256,
            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_384,
            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512,

            SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_1,
            SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256,
            SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384,
            SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512,

            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_1,
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256,
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_384,
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,

            SymmetricEncryptionAlgorithm.AES_128.GCM,
            SymmetricEncryptionAlgorithm.AES_192.GCM,
            SymmetricEncryptionAlgorithm.AES_256.GCM,

            SymmetricEncryptionAlgorithm.ChaCha20Poly1305,

            ) { alg ->

            withData(
                nameFn = { "${it?.size} Bytes" },
                Random.nextBytes(1),
                Random.nextBytes(17),
                Random.nextBytes(18),
                Random.nextBytes(33),
                Random.nextBytes(256),
                null
            ) { iv ->

                val key = alg.randomKey(InsecureRandom)
                if (iv != null) key.andPredefinedNonce(iv) shouldNot succeed
                else key.encrypt(Random.nextBytes(32)) should succeed
                key.andPredefinedNonce(alg.randomNonce()).getOrThrow().encrypt(Random.nextBytes(32)) should succeed
                key.encrypt(Random.nextBytes(32)) should succeed

                if (alg.authCapability is AuthCapability.Authenticated)
                    key.encrypt(Random.nextBytes(32))
                        .getOrThrow().algorithm.isAuthenticated() shouldBe true
                else if (alg.authCapability is AuthCapability.Unauthenticated)
                    key.encrypt(Random.nextBytes(32))
                        .getOrThrow().algorithm.isAuthenticated() shouldBe false
            }
        }
    }


    "Illegal Key Size" - {
        withDataSuites(
            SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN,

            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_1,
            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256,
            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_384,
            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512,

            SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_1,
            SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256,
            SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384,
            SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512,

            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_1,
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256,
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_384,
            SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,

            SymmetricEncryptionAlgorithm.AES_128.GCM,
            SymmetricEncryptionAlgorithm.AES_192.GCM,
            SymmetricEncryptionAlgorithm.AES_256.GCM,

            SymmetricEncryptionAlgorithm.ChaCha20Poly1305

        ) { alg ->

            withData(
                nameFn = { "${it.size} Bytes" },
                Random.nextBytes(0),
                Random.nextBytes(1),
                Random.nextBytes(17),
                Random.nextBytes(18),
                Random.nextBytes(33), //cannot use 16, 24, or 32
                Random.nextBytes(256),

                ) { keyBytes ->

                when (alg.hasDedicatedMac()) {
                    true -> alg.keyFrom(keyBytes, keyBytes) //never do this in production!
                    false -> alg.keyFrom(keyBytes)
                } shouldNot succeed

                val key = when (alg.hasDedicatedMac()) {
                    true -> alg.keyFrom(
                        alg.randomKey(InsecureRandom).encryptionKey.getOrThrow(),
                        alg.randomKey(InsecureRandom).encryptionKey.getOrThrow()
                    )

                    false -> alg.keyFrom(alg.randomKey(InsecureRandom).secretKey.getOrThrow())
                }.getOrThrow()



                key.encrypt(Random.nextBytes(32)) should succeed
                key.andPredefinedNonce(alg.randomNonce()).getOrThrow()
                    .encrypt(data = Random.nextBytes(32)) should succeed

                if (alg.authCapability is AuthCapability.Authenticated)
                    alg.randomKey(InsecureRandom).encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it should succeed
                        it.getOrThrow().algorithm.isAuthenticated() shouldBe true
                    }
                else if (alg.authCapability is AuthCapability.Unauthenticated)
                    alg.randomKey(InsecureRandom).encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it should succeed
                        it.getOrThrow().algorithm.isAuthenticated() shouldBe false
                    }
            }
        }
    }

    "CBC.PLAIN" - {

        withDataSuites(
            SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN,
        ) {
            withDataSuites(
                nameFn = { "${it.size} Bytes" },
                InsecureRandom.nextBytes(5),
                InsecureRandom.nextBytes(15),
                InsecureRandom.nextBytes(16),
                InsecureRandom.nextBytes(17),
                InsecureRandom.nextBytes(31),
                InsecureRandom.nextBytes(32),
                InsecureRandom.nextBytes(33),
                InsecureRandom.nextBytes(256),
                InsecureRandom.nextBytes(257),
                InsecureRandom.nextBytes(1257),
                InsecureRandom.nextBytes(21257),
            ) { plaintext ->

                val key = runBlocking { it.randomKey(InsecureRandom) }

                withData(
                    nameFn = { "IV: " + it?.toHexString()?.substring(0..8) },
                    it.randomNonce(),
                    it.randomNonce(),
                    null
                ) { iv ->

                    val ciphertext =
                        if (iv != null) key.andPredefinedNonce(iv).getOrThrow().encrypt(plaintext).getOrThrow()
                        else key.encrypt(plaintext).getOrThrow()

                    ciphertext.nonce.shouldNotBeNull()
                    if (iv != null) ciphertext.nonce.size shouldBe iv.size
                    ciphertext.nonce.size shouldBe it.nonceSize.bytes.toInt()
                    iv?.let { ciphertext.nonce shouldBe iv }
                    ciphertext.algorithm.isAuthenticated() shouldBe false


                    val decrypted = ciphertext.decrypt(key).getOrThrow()
                    decrypted shouldBe plaintext


                    val wrongDecrypted = ciphertext.decrypt(it.randomKey(InsecureRandom))
                    //We're not authenticated, so from time to time, we won't run into a padding error for specific plaintext sizes
                    wrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }

                    val wrongCiphertext =
                        ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                            InsecureRandom.nextBytes(ciphertext.encryptedData.size)
                        ).getOrThrow()

                    val wrongWrongDecrypted = wrongCiphertext.decrypt(it.randomKey(InsecureRandom))
                    withClue(
                        "KEY: ${
                            key.secretKey.getOrThrow().toHexString()
                        }, wrongCiphertext: ${wrongCiphertext.encryptedData.toHexString()}, ciphertext: ${ciphertext.encryptedData.toHexString()}, iv: ${wrongCiphertext.nonce?.toHexString()}"
                    ) {
                        //we're not authenticated, so from time to time, this succeeds
                        //wrongWrongDecrypted shouldNot succeed
                        //instead, we test differently:
                        wrongWrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }
                    }
                    val wrongRightDecrypted = wrongCiphertext.decrypt(key)
                    withClue(
                        "KEY: ${
                            key.secretKey.getOrThrow().toHexString()
                        }, wrongCiphertext: ${wrongCiphertext.encryptedData.toHexString()}, ciphertext: ${ciphertext.encryptedData.toHexString()}, iv: ${wrongCiphertext.nonce?.toHexString()}"
                    ) {
                        //we're not authenticated, so from time to time, this succeeds
                        //wrongRightDecrypted shouldNot succeed
                        //instead, we test differently:
                        wrongRightDecrypted.onSuccess { value -> value shouldNotBe plaintext }
                    }
                    val wrongIV =
                        ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce.asList().shuffled().toByteArray())
                            .from(
                                encryptedData = ciphertext.encryptedData
                            ).getOrThrow()


                    if (plaintext.size > it.blockSize.bytes.toInt()) { //cannot test like that for ciphertexts shorter than IV
                        val wrongIVDecrypted = wrongIV.decrypt(key)
                        wrongIVDecrypted should succeed //no padding errors!
                        wrongIVDecrypted shouldNotBe plaintext
                    }

                }
            }
        }
    }

    "GCM + ChaCha-Poly1503" - {
        withDataSuites(
            SymmetricEncryptionAlgorithm.AES_128.GCM,
            SymmetricEncryptionAlgorithm.AES_192.GCM,
            SymmetricEncryptionAlgorithm.AES_256.GCM,

            SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        ) { alg ->

            withDataSuites(
                nameFn = { "${it.size} Bytes" },
                InsecureRandom.nextBytes(5),
                InsecureRandom.nextBytes(15),
                InsecureRandom.nextBytes(16),
                InsecureRandom.nextBytes(17),
                InsecureRandom.nextBytes(31),
                InsecureRandom.nextBytes(32),
                InsecureRandom.nextBytes(33),
                InsecureRandom.nextBytes(256),
                InsecureRandom.nextBytes(257),
                InsecureRandom.nextBytes(1257),
                InsecureRandom.nextBytes(21257),
            ) { plaintext ->
                val key = runBlocking { alg.randomKey(InsecureRandom) }
                withDataSuites(
                    nameFn = { "IV: " + it?.toHexString()?.substring(0..8) },
                    alg.randomNonce(),
                    alg.randomNonce(),
                    null
                ) { iv ->

                    withData(
                        nameFn = { "AAD: " + it?.toHexString() },
                        InsecureRandom.nextBytes(32),
                        null
                    ) { aad ->
                        key.encrypt(plaintext, aad)
                        val ciphertext =
                            if (iv != null) key.andPredefinedNonce(iv).getOrThrow().encrypt(plaintext, aad).getOrThrow()
                            else key.encrypt(plaintext, aad).getOrThrow()

                        ciphertext.nonce.shouldNotBeNull()
                        ciphertext.nonce.size shouldBe alg.nonceSize.bytes.toInt()
                        if (iv != null) ciphertext.nonce shouldBe iv
                        ciphertext.algorithm.authCapability.shouldBeInstanceOf<AuthCapability.Authenticated<*>>()
                        val decrypted = ciphertext.decrypt(key, aad ?: byteArrayOf()).getOrThrow()
                        decrypted shouldBe plaintext


                        val wrongDecrypted = ciphertext.decrypt(alg.randomKey(InsecureRandom))
                        wrongDecrypted shouldNot succeed

                        val wrongCiphertext = alg.sealedBox.withNonce(ciphertext.nonce).from(
                            InsecureRandom.nextBytes(ciphertext.encryptedData.size),
                            authTag = ciphertext.authTag,
                        ).getOrThrow()


                        val wrongWrongDecrypted =
                            wrongCiphertext.decrypt(alg.randomKey(InsecureRandom), aad ?: byteArrayOf())
                        wrongWrongDecrypted shouldNot succeed

                        val wrongRightDecrypted = wrongCiphertext.decrypt(key)
                        wrongRightDecrypted shouldNot succeed

                        val wrongIV = alg.sealedBox.withNonce(ciphertext.nonce.asList().shuffled().toByteArray()).from(
                            ciphertext.encryptedData,
                            authTag = ciphertext.authTag,
                        ).getOrThrow()

                        val wrongIVDecrypted = wrongIV.decrypt(key, aad ?: byteArrayOf())
                        wrongIVDecrypted shouldNot succeed


                        if (aad != null) {
                            //missing aad
                            alg.sealedBox.withNonce(ciphertext.nonce).from(
                                encryptedData = ciphertext.encryptedData,
                                authTag = ciphertext.authTag,
                            ).getOrThrow().decrypt(key) shouldNot succeed

                        }
                        //shuffled auth tag
                        alg.sealedBox.withNonce(ciphertext.nonce).from(
                            ciphertext.encryptedData,
                            authTag = ciphertext.authTag.asList().shuffled().toByteArray(),
                        ).getOrThrow().decrypt(key, aad ?: byteArrayOf()) shouldNot succeed
                    }
                }
            }
        }
    }

    "CBC+HMAC" - {
        withDataSuites(
            nameFn = { it.first },
            "Default" to DefaultMacInputCalculation,
            "Oklahoma MAC" to { ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray? ->
                "Oklahoma".encodeToByteArray() +
                        (iv ?: byteArrayOf()) +
                        (aad ?: byteArrayOf()) +
                        ciphertext
            }) { (_, macInputFun) ->
            withDataSuites(
                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_1.Custom(
                    HMAC.SHA1.outputLength,
                    DefaultMacAuthTagTransformation,
                    macInputFun
                ),
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_1.Custom(
                    HMAC.SHA1.outputLength,
                    DefaultMacAuthTagTransformation,
                    macInputFun
                ),
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_1.Custom(
                    HMAC.SHA1.outputLength,
                    DefaultMacAuthTagTransformation,
                    macInputFun
                ),


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256.Custom(
                    HMAC.SHA256.outputLength,
                    macInputFun
                ),
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256.Custom(
                    HMAC.SHA256.outputLength,
                    macInputFun
                ),
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256.Custom(
                    HMAC.SHA256.outputLength,
                    macInputFun
                ),


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_384.Custom(
                    HMAC.SHA384.outputLength,
                    macInputFun
                ),
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384.Custom(
                    HMAC.SHA384.outputLength,
                    macInputFun
                ),
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_384.Custom(
                    HMAC.SHA384.outputLength,
                    macInputFun
                ),


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512.Custom(
                    HMAC.SHA512.outputLength,
                    macInputFun,
                ),
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512.Custom(
                    HMAC.SHA512.outputLength,
                    macInputFun,
                ),
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512.Custom(
                    HMAC.SHA512.outputLength,
                    macInputFun,
                ),
            ) {
                withDataSuites(
                    nameFn = { "${it.size} Bytes" },
                    InsecureRandom.nextBytes(16),
                    byteArrayOf(),
                    InsecureRandom.nextBytes(5),
                    InsecureRandom.nextBytes(15),
                    InsecureRandom.nextBytes(17),
                    InsecureRandom.nextBytes(31),
                    InsecureRandom.nextBytes(32),
                    InsecureRandom.nextBytes(33),
                    InsecureRandom.nextBytes(256),
                    InsecureRandom.nextBytes(257),
                    InsecureRandom.nextBytes(1257),
                    InsecureRandom.nextBytes(21257),
                ) { plaintext ->

                    val secretKey = runBlocking { it.randomKey(InsecureRandom).encryptionKey.getOrThrow() }

                    withDataSuites(
                        nameFn = { "MAC KEY $it" },
                        16, 32, 64, 128, secretKey.size
                    ) { macKeyLen ->

                        val key = runBlocking { it.randomKey(macKeyLen.bytes, InsecureRandom) }

                        withDataSuites(
                            nameFn = { "IV: " + it?.toHexString()?.substring(0..8) },
                            InsecureRandom.nextBytes((it.nonceSize.bytes).toInt()),
                            InsecureRandom.nextBytes((it.nonceSize.bytes).toInt()),
                            null
                        ) { iv ->
                            withData(
                                nameFn = { "AAD: " + it?.toHexString()?.substring(0..8) },
                                InsecureRandom.nextBytes(32),
                                null
                            ) { aad ->
                                val ciphertext =
                                    if (iv != null) key.andPredefinedNonce(iv).getOrThrow().encrypt(plaintext, aad)
                                        .getOrThrow()
                                    else key.encrypt(plaintext, aad).getOrThrow()
                                val manilaAlg = it.Custom(ciphertext.authTag.size.bytes)
                                { _, _, _ -> "Manila".encodeToByteArray() }

                                val manilaKey = SymmetricKey.WithDedicatedMac.RequiringNonce(
                                    manilaAlg,
                                    key.encryptionKey.getOrThrow(),
                                    key.macKey.getOrThrow()
                                )
                                if (iv != null) manilaKey.andPredefinedNonce(iv).getOrThrow().encrypt(plaintext, aad)
                                    .getOrThrow() shouldNotBe ciphertext
                                manilaKey.encrypt(plaintext, aad).getOrThrow() shouldNotBe ciphertext

                                //no randomness. must be equal
                                val randomIV = it.randomNonce()
                                manilaKey.andPredefinedNonce(randomIV).getOrThrow().encrypt(plaintext, aad)
                                    .getOrThrow() shouldBe
                                        manilaKey.andPredefinedNonce(randomIV).getOrThrow().encrypt(plaintext, aad)
                                            .getOrThrow()

                                if (iv != null) ciphertext.nonce shouldBe iv
                                ciphertext.nonce.shouldNotBeNull()
                                ciphertext.nonce.size shouldBe it.nonceSize.bytes.toInt()
                                ciphertext.algorithm.authCapability.shouldBeInstanceOf<AuthCapability.Authenticated<*>>()

                                val decrypted = ciphertext.decrypt(key, aad ?: byteArrayOf()).getOrThrow()
                                decrypted shouldBe plaintext

                                val wrongDecrypted = ciphertext.decrypt(it.randomKey(InsecureRandom))
                                wrongDecrypted shouldNot succeed

                                val wrongCiphertext =
                                    ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                                        InsecureRandom.nextBytes(ciphertext.encryptedData.size),
                                        authTag = ciphertext.authTag,
                                    ).getOrThrow()

                                val wrongWrongDecrypted =
                                    wrongCiphertext.decrypt(it.randomKey(InsecureRandom), aad ?: byteArrayOf())
                                wrongWrongDecrypted shouldNot succeed

                                val wrongRightDecrypted =
                                    wrongCiphertext.decrypt(key)
                                wrongRightDecrypted shouldNot succeed

                                val wrongIV =
                                    ciphertext.algorithm.sealedBox.withNonce(
                                        ciphertext.nonce.asList().shuffled().toByteArray()
                                    ).from(
                                        ciphertext.encryptedData,
                                        ciphertext.authTag,
                                    ).getOrThrow()

                                val wrongIVDecrypted = wrongIV.decrypt(key, aad ?: byteArrayOf())
                                wrongIVDecrypted shouldNot succeed
                                ciphertext.algorithm.sealedBox.withNonce(
                                    ciphertext.nonce.asList().shuffled().toByteArray()
                                ).from(
                                    ciphertext.encryptedData,
                                    authTag = ciphertext.authTag,
                                ).getOrThrow().decrypt(key, aad ?: byteArrayOf()) shouldNot succeed

                                ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                                    ciphertext.encryptedData,
                                    authTag = ciphertext.authTag,
                                ).getOrThrow().decrypt(
                                    SymmetricKey.WithDedicatedMac.RequiringNonce(
                                        ciphertext.algorithm,
                                        key.encryptionKey.getOrThrow(),
                                        dedicatedMacKey = key.macKey.getOrThrow().asList().shuffled().toByteArray()
                                    ), aad ?: byteArrayOf()
                                ) shouldNot succeed

                                if (aad != null) {
                                    ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                                        ciphertext.encryptedData,
                                        ciphertext.authTag,
                                    ).getOrThrow().decrypt(key) shouldNot succeed
                                }

                                ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                                    ciphertext.encryptedData,
                                    ciphertext.authTag.asList().shuffled().toByteArray(),
                                ).getOrThrow().decrypt(key, aad ?: byteArrayOf()) shouldNot succeed
                                ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                                    ciphertext.encryptedData,
                                    ciphertext.authTag.asList().shuffled().toByteArray(),
                                ).getOrThrow().decrypt(it.Custom(ciphertext.authTag.size.bytes) { _, _, _ ->
                                    "Szombathely".encodeToByteArray()
                                }.let {
                                    SymmetricKey.WithDedicatedMac.RequiringNonce(
                                        it,
                                        key.encryptionKey.getOrThrow(),
                                        key.macKey.getOrThrow()
                                    )
                                }, aad ?: byteArrayOf()) shouldNot succeed
                            }

                        }
                    }
                }
            }
        }
    }

    "ECB + WRAP" - {
        withDataSuites(
            SymmetricEncryptionAlgorithm.AES_128.ECB,
            SymmetricEncryptionAlgorithm.AES_192.ECB,
            SymmetricEncryptionAlgorithm.AES_256.ECB,
            SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394,
            SymmetricEncryptionAlgorithm.AES_192.WRAP.RFC3394,
            SymmetricEncryptionAlgorithm.AES_256.WRAP.RFC3394,

            ) { alg ->

            withData(
                nameFn = { "data: ${it.size} bytes" },
                Random.nextBytes(19),
                Random.nextBytes(1),
                Random.nextBytes(1234),
                Random.nextBytes(54),
                Random.nextBytes(16),
                Random.nextBytes(32),
                Random.nextBytes(256),
                Random.nextBytes(512),
                Random.nextBytes(1024),
                Random.nextBytes(8),
                Random.nextBytes(16),
                Random.nextBytes(48),
                Random.nextBytes(24),
                Random.nextBytes(72),
            ) { data ->

                val secretKey = alg.randomKey(InsecureRandom)

                //CBC
                if (alg !is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394) {

                    val own = secretKey.encrypt(data).getOrThrow()


                    own.decrypt(secretKey).getOrThrow() shouldBe data

                    //we might get lucky here
                    own.decrypt(own.algorithm.randomKey(InsecureRandom)).onSuccess {
                        it shouldNotBe data
                    }

                    alg.sealedBox.from(own.encryptedData).getOrThrow().decrypt(secretKey) should succeed
                } else {


                    val shouldSucceed = (data.size >= 16) && (data.size % 8 == 0)
                    val trial = secretKey.encrypt(data)

                    if (shouldSucceed) trial should succeed
                    else trial shouldNot succeed




                    if (shouldSucceed) {
                        val own = trial.getOrThrow()


                        own.decrypt(secretKey).getOrThrow() shouldBe data

                        //we might get lucky here
                        own.decrypt(own.algorithm.randomKey(InsecureRandom)).onSuccess {
                            it shouldNotBe data
                        }

                        alg.sealedBox.from(own.encryptedData).getOrThrow().decrypt(secretKey) should succeed
                    }
                }
            }
        }
    }


    val allAlgorithms = listOf(
        SymmetricEncryptionAlgorithm.AES_128.ECB,
        SymmetricEncryptionAlgorithm.AES_192.ECB,
        SymmetricEncryptionAlgorithm.AES_256.ECB,
        SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
        SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
        SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN,
        SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256,
        SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256,
        SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256,
        SymmetricEncryptionAlgorithm.AES_128.GCM,
        SymmetricEncryptionAlgorithm.AES_192.GCM,
        SymmetricEncryptionAlgorithm.AES_256.GCM,

        SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394,
        SymmetricEncryptionAlgorithm.AES_192.WRAP.RFC3394,
        SymmetricEncryptionAlgorithm.AES_256.WRAP.RFC3394,

        SymmetricEncryptionAlgorithm.ChaCha20Poly1305,
    )


    "Equality" - {
        withDataSuites(allAlgorithms) { alg ->
            withData(
                nameFn = { "data: ${it.size} bytes" },
                //multiples of 8, so AES-KW works
                Random.nextBytes(192),
                Random.nextBytes(24),
                Random.nextBytes(32),
                Random.nextBytes(56),
                Random.nextBytes(64),
                Random.nextBytes(256),
                Random.nextBytes(1024),
                Random.nextBytes(4096),
            ) { plaintext ->
                alg.randomKey(InsecureRandom).also { key ->
                    when (alg.hasDedicatedMac()) {
                        true -> {
                            key shouldBe alg.keyFrom(
                                (key as SymmetricKey.WithDedicatedMac).encryptionKey.getOrThrow(),
                                (key as SymmetricKey.WithDedicatedMac<*>).macKey.getOrThrow()
                            ).getOrThrow()

                            key shouldNotBe alg.keyFrom(
                                key.encryptionKey.getOrThrow(),
                                (key as SymmetricKey.WithDedicatedMac<*>).macKey.getOrThrow().asList().shuffled()
                                    .toByteArray()
                            ).getOrThrow()
                            key shouldNotBe alg.keyFrom(
                                key.encryptionKey.getOrThrow().asList().shuffled().toByteArray(),
                                (key as SymmetricKey.WithDedicatedMac<*>).macKey.getOrThrow()
                            ).getOrThrow()
                            key shouldNotBe alg.keyFrom(
                                key.encryptionKey.getOrThrow().asList().shuffled().toByteArray(),
                                (key as SymmetricKey.WithDedicatedMac<*>).macKey.getOrThrow().asList().shuffled()
                                    .toByteArray()
                            ).getOrThrow()
                        }

                        false -> key shouldBe alg.keyFrom((key as SymmetricKey.Integrated).secretKey.getOrThrow())
                            .getOrThrow()
                    }
                }


                if (alg.isAuthenticated()) {
                    val aad = plaintext.asList().shuffled().toByteArray()
                    if (!alg.requiresNonce()) alg.randomKey(InsecureRandom).let { key ->
                        key.encrypt(plaintext, aad).getOrThrow() shouldBe key.encrypt(plaintext, aad).getOrThrow()
                        key.encrypt(plaintext, plaintext).getOrThrow() shouldNotBe key.encrypt(plaintext, aad)
                            .getOrThrow()
                    }
                    else alg.randomKey(InsecureRandom).let { key ->

                        key.encrypt(plaintext, aad).getOrThrow() shouldNotBe key.encrypt(plaintext, aad).getOrThrow()

                        val nonce = alg.randomNonce()
                        key.andPredefinedNonce(nonce).getOrThrow()
                            .encrypt(plaintext).getOrThrow() shouldBe key.andPredefinedNonce(nonce).getOrThrow()
                            .encrypt(plaintext).getOrThrow()

                        key.andPredefinedNonce(nonce).getOrThrow()
                            .encrypt(plaintext).getOrThrow() shouldNotBe key.andPredefinedNonce(alg.randomNonce())
                            .getOrThrow()
                            .encrypt(plaintext).getOrThrow()
                    }
                } else {
                    if (!alg.requiresNonce()) alg.randomKey(InsecureRandom).also { key ->
                        key.encrypt(plaintext).getOrThrow() shouldBe key.encrypt(plaintext).getOrThrow()
                    } else alg.randomKey(InsecureRandom).let { key ->

                        key.encrypt(plaintext).getOrThrow() shouldNotBe key.encrypt(plaintext).getOrThrow()

                        val nonce = alg.randomNonce()
                        key.andPredefinedNonce(nonce).getOrThrow()
                            .encrypt(plaintext).getOrThrow() shouldBe key.andPredefinedNonce(nonce).getOrThrow()
                            .encrypt(plaintext).getOrThrow()

                        key.andPredefinedNonce(nonce).getOrThrow()
                            .encrypt(plaintext).getOrThrow() shouldNotBe key.andPredefinedNonce(alg.randomNonce())
                            .getOrThrow()
                            .encrypt(plaintext).getOrThrow()
                    }
                }

                allAlgorithms.filterNot { it /*check for same instance*/ === alg }.forEach { wrongAlg ->
                    alg shouldNotBe wrongAlg
                    alg.randomKey(InsecureRandom) shouldNotBe wrongAlg.randomKey(InsecureRandom)
                    if (alg.keySize == wrongAlg.keySize) {
                        if (alg.isAuthenticated() && wrongAlg.isAuthenticated()) {
                            if (alg.hasDedicatedMac() && wrongAlg.hasDedicatedMac()) {
                                alg.randomKey(InsecureRandom).let { key ->
                                    wrongAlg.keyFrom(
                                        key.encryptionKey.getOrThrow(),
                                        key.macKey.getOrThrow() /*size will not match, but it will get us a valid key*/
                                    ).getOrThrow() shouldNotBe key
                                }
                            } else if (!wrongAlg.hasDedicatedMac() && !alg.hasDedicatedMac()) {
                                alg.randomKey(InsecureRandom).let { key ->
                                    wrongAlg.keyFrom(
                                        key.secretKey.getOrThrow(),
                                    ).getOrThrow() shouldNotBe key
                                }
                            }
                        }
                    }

                    val box = when (alg.requiresNonce()) {
                        true -> when (alg.isAuthenticated()) {
                            true -> alg.sealedBox.withNonce(alg.randomNonce()).from(
                                plaintext,
                                Random.nextBytes(alg.authTagSize.bytes.toInt()),
                            )

                            false -> alg.sealedBox.withNonce(alg.randomNonce()).from(plaintext)
                        }

                        false -> when (alg.isAuthenticated()) {
                            true -> alg.sealedBox.from(
                                plaintext,
                                Random.nextBytes(alg.authTagSize.bytes.toInt()),
                            )

                            false -> alg.sealedBox.from(plaintext)
                        }
                    }.getOrThrow()

                    val box2 = when (wrongAlg.requiresNonce()) {
                        true -> when (wrongAlg.isAuthenticated()) {
                            true -> wrongAlg.sealedBox.withNonce(
                                if (box.hasNonce() && box.nonce.size == wrongAlg.nonceSize.bytes.toInt()) box.nonce else
                                    wrongAlg.randomNonce()
                            ).from(

                                plaintext,
                                if (box.isAuthenticated() && box.authTag.size == wrongAlg.authTagSize.bytes.toInt()) box.authTag else
                                    Random.nextBytes(wrongAlg.authTagSize.bytes.toInt()),
                            )

                            false -> wrongAlg.sealedBox.withNonce(
                                if (box.hasNonce() && box.nonce.size == wrongAlg.nonceSize.bytes.toInt()) box.nonce else
                                    wrongAlg.randomNonce()
                            ).from(
                                plaintext
                            )
                        }

                        false -> when (wrongAlg.isAuthenticated()) {
                            true -> wrongAlg.sealedBox.from(
                                plaintext,
                                if (box.isAuthenticated() && box.authTag.size == wrongAlg.authTagSize.bytes.toInt()) box.authTag else
                                    Random.nextBytes(wrongAlg.authTagSize.bytes.toInt()),
                            )

                            false -> wrongAlg.sealedBox.from(plaintext)
                        }
                    }.getOrThrow()

                    box shouldNotBe box2
                }
            }
        }
    }


    "Edge Cases " - {
        "all good" - {
            withDataSuites(
                SymmetricEncryptionAlgorithm.AES_128.ECB,
                SymmetricEncryptionAlgorithm.AES_192.ECB,
                SymmetricEncryptionAlgorithm.AES_256.ECB,
                SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256,
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256,
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256,
                SymmetricEncryptionAlgorithm.AES_128.GCM,
                SymmetricEncryptionAlgorithm.AES_192.GCM,
                SymmetricEncryptionAlgorithm.AES_256.GCM,
                /*NO WRAP, because it has constraints on input size*/
                SymmetricEncryptionAlgorithm.ChaCha20Poly1305,

                ) { alg ->

                withData(0, 1, 4096) { sz ->
                    val data = Random.nextBytes(sz)
                    val key = alg.randomKey(InsecureRandom)
                    key.encrypt(data).getOrThrow().decrypt(key).getOrThrow() shouldBe data
                }
            }
        }

        "algorithm mismatch" - {
            withDataSuites(allAlgorithms) { alg ->
                withData(allAlgorithms.filterNot { it == alg }) { wrongAlg ->
                    val encrypted =
                        alg.randomKey(InsecureRandom).encrypt(Random.nextBytes(64)/*works with wrapping*/).getOrThrow()
                    val wrongKey = wrongAlg.randomKey(InsecureRandom)

                    encrypted.decrypt(wrongKey) shouldNot succeed

                }
            }
        }
        "illegal key sizes" - {
            withDataSuites(allAlgorithms) { alg ->
                val wrongSized = mutableListOf<Int>()
                while (wrongSized.size < 100) {
                    val wrong = Random.nextUInt(until = 1025u).toInt()
                    if (wrong != alg.keySize.bytes.toInt())
                        wrongSized += wrong
                }
                withData(wrongSized) { sz ->
                    when (alg.hasDedicatedMac()) {
                        true -> {
                            alg.keyFrom(
                                Random.nextBytes(sz),
                                alg.randomKey(InsecureRandom).encryptionKey.getOrThrow() /*mac key should not trigger, as it is unconstrained*/
                            )
                        }

                        false -> {
                            alg.keyFrom(Random.nextBytes(sz))
                        }
                    } shouldNot succeed
                }
            }
        }

        "illegal nonce sizes" - {
            withDataSuites(allAlgorithms.filter { it.requiresNonce() }) { alg ->
                alg as SymmetricEncryptionAlgorithm.RequiringNonce<*, *>
                val wrongSized = mutableListOf<Int>()
                while (wrongSized.size < 100) {
                    val wrong = Random.nextUInt(until = 1025u).toInt()
                    if (wrong != alg.nonceSize.bytes.toInt())
                        wrongSized += wrong
                }
                withData(wrongSized) { sz ->
                    alg.randomKey(InsecureRandom).andPredefinedNonce(Random.nextBytes(sz)) shouldNot succeed
                }

            }
        }
    }
}

