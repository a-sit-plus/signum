@file:OptIn(SecretExposure::class, HazardousMaterials::class)

package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.awesn1.encoding.encodeTo4Bytes
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import at.asitplus.signum.supreme.InsecureRandom
import at.asitplus.signum.supreme.symmetric.discouraged.andPredefinedNonce
import at.asitplus.signum.supreme.symmetric.discouraged.encrypt
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.assertions.withClue
import io.kotest.engine.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.collections.mapNotNull
import kotlin.random.Random
import kotlin.random.nextUInt
import kotlin.time.Clock

val SymmetricTest by matrixSuite {

    "README" {

        //base case
        val secret = "Top Secret".encodeToByteArray()
        val authenticatedData = "Bottom Secret".encodeToByteArray()
        val secretKey = SymmetricEncryptionAlgorithm.ChaCha20Poly1305.randomKey(InsecureRandom)
        val encrypted = secretKey.encrypt(secret, authenticatedData)
        encrypted.decrypt(secretKey, authenticatedData) shouldBe secret

        //getting data from external

        val algo = SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        val nonce = encrypted.nonce
        val ciphertext = encrypted.encryptedData
        val authTag = encrypted.authTag
        val externalAAD = authenticatedData
        val keyBytes = secretKey.secretKey

        val preSharedKey = algo.keyFrom(keyBytes)

        val box = algo.sealedBox.withNonce(nonce).from(ciphertext, authTag)
        box.decrypt(preSharedKey, /*also pass AAD*/ externalAAD) shouldBe secret

        //direct decryption
        preSharedKey.decrypt(nonce, ciphertext, authTag, externalAAD) shouldBe secret

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
        )

        //because everything is structured, decryption is simple
        val recovered = sealedBox.decrypt(key, aad)

        recovered shouldBe payload //success!

        //we can also manually construct the sealed box, if we know the algorithm:
        val reconstructed = algorithm.sealedBox.withNonce(sealedBox.nonce).from(
            encryptedData = sealedBox.encryptedData, /*Could also access authenticatedCipherText*/
            authTag = sealedBox.authTag,
        )

        val manuallyRecovered = reconstructed.decrypt(
            key,
            authenticatedData = aad,
        )

        manuallyRecovered shouldBe payload //great success!

        //if we just know algorithm and key bytes, we can also construct a symmetric key
        reconstructed.decrypt(
            algorithm.keyFrom(key.encryptionKey, key.macKey),
            aad
        ) shouldBe payload //greatest success!
    }


    "Illegal IV Size" - {
        data(
            listOf(
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
            )
        ) - { alg ->

            data(
                listOf(
                    Random.nextBytes(1),
                    Random.nextBytes(17),
                    Random.nextBytes(18),
                    Random.nextBytes(33),
                    Random.nextBytes(256),
                    null
                ), nameFn = { "${it?.size} Bytes" }) test { iv ->

                val key = alg.randomKey(InsecureRandom)
                if (iv != null) shouldThrow<IllegalArgumentException> { key.andPredefinedNonce(iv) }
                else shouldNotThrowAny { key.encrypt(Random.nextBytes(32)) }
                shouldNotThrowAny { key.andPredefinedNonce(alg.randomNonce()).encrypt(Random.nextBytes(32)) }
                shouldNotThrowAny { key.encrypt(Random.nextBytes(32)) }

                if (alg.isAuthenticated())
                    key.encrypt(Random.nextBytes(32)).algorithm.isAuthenticated() shouldBe true
                else
                    key.encrypt(Random.nextBytes(32)).algorithm.isAuthenticated() shouldBe false
            }
        }
    }


    "Illegal Key Size" - {
        data(
            listOf(
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
            )
        ) - { alg ->

            data(
                listOf(
                    Random.nextBytes(0),
                    Random.nextBytes(1),
                    Random.nextBytes(17),
                    Random.nextBytes(18),
                    Random.nextBytes(33), //cannot use 16, 24, or 32
                    Random.nextBytes(256)
                ), nameFn = { "${it.size} Bytes" }) test { keyBytes ->

                shouldThrow<IllegalArgumentException> {
                    when (alg.hasDedicatedMac()) {
                        true -> alg.keyFrom(keyBytes, keyBytes) //never do this in production!
                        false -> alg.keyFrom(keyBytes)
                    }
                }

                val key = when (alg.hasDedicatedMac()) {
                    true -> alg.keyFrom(
                        alg.randomKey(InsecureRandom).encryptionKey,
                        alg.randomKey(InsecureRandom).encryptionKey
                    )

                    false -> alg.keyFrom(alg.randomKey(InsecureRandom).secretKey)
                }



                shouldNotThrowAny { key.encrypt(Random.nextBytes(32)) }
                shouldNotThrowAny { key.andPredefinedNonce(alg.randomNonce()).encrypt(data = Random.nextBytes(32)) }

                if (alg.isAuthenticated())
                    alg.randomKey(InsecureRandom).encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it.algorithm.isAuthenticated() shouldBe true
                    }
                else
                    alg.randomKey(InsecureRandom).encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it.algorithm.isAuthenticated() shouldBe false
                    }
            }
        }
    }

    "CBC.PLAIN" - {

        data(
            listOf(
                SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN
            )
        ) - {
            data(
                listOf(
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
                    InsecureRandom.nextBytes(21257)
                ), nameFn = { "${it.size} Bytes" }) - { plaintext ->

                val key = runBlocking { it.randomKey(InsecureRandom) }

                data(
                    listOf(it.randomNonce(), it.randomNonce(), null),
                    nameFn = { "IV: " + it?.toHexString()?.substring(0..8) }) test { iv ->

                    val ciphertext =
                        if (iv != null) key.andPredefinedNonce(iv).encrypt(plaintext)
                        else key.encrypt(plaintext)

                    ciphertext.nonce.shouldNotBeNull()
                    if (iv != null) ciphertext.nonce.size shouldBe iv.size
                    ciphertext.nonce.size shouldBe it.nonceSize.bytes.toInt()
                    iv?.let { ciphertext.nonce shouldBe iv }
                    ciphertext.algorithm.isAuthenticated() shouldBe false


                    val decrypted = ciphertext.decrypt(key)
                    decrypted shouldBe plaintext


                    val wrongDecrypted = runCatching { ciphertext.decrypt(it.randomKey(InsecureRandom)) }
                    //We're not authenticated, so from time to time, we won't run into a padding error for specific plaintext sizes
                    wrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }

                    val wrongCiphertext =
                        ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                            InsecureRandom.nextBytes(ciphertext.encryptedData.size)
                        )

                    val wrongWrongDecrypted = runCatching { wrongCiphertext.decrypt(it.randomKey(InsecureRandom)) }
                    withClue(
                        "KEY: ${
                            key.secretKey.toHexString()
                        }, wrongCiphertext: ${wrongCiphertext.encryptedData.toHexString()}, ciphertext: ${ciphertext.encryptedData.toHexString()}, iv: ${wrongCiphertext.nonce?.toHexString()}"
                    ) {
                        //we're not authenticated, so from time to time, this succeeds
                        //instead, we test differently:
                        wrongWrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }
                    }
                    val wrongRightDecrypted = runCatching { wrongCiphertext.decrypt(key) }
                    withClue(
                        "KEY: ${
                            key.secretKey.toHexString()
                        }, wrongCiphertext: ${wrongCiphertext.encryptedData.toHexString()}, ciphertext: ${ciphertext.encryptedData.toHexString()}, iv: ${wrongCiphertext.nonce.toHexString()}"
                    ) {
                        //we're not authenticated, so from time to time, this succeeds
                        //instead, we test differently:
                        wrongRightDecrypted.onSuccess { value -> value shouldNotBe plaintext }
                    }
                    val wrongIV =
                        ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce.asList().shuffled().toByteArray())
                            .from(
                                encryptedData = ciphertext.encryptedData
                            )


                    if (plaintext.size > it.blockSize.bytes.toInt()) { //cannot test like that for ciphertexts shorter than IV
                        val wrongIVDecrypted = wrongIV.decrypt(key)
                        wrongIVDecrypted shouldNotBe plaintext
                    }

                }
            }
        }
    }

    "GCM + ChaCha-Poly1503" - {
        data(
            listOf(
                SymmetricEncryptionAlgorithm.AES_128.GCM,
                SymmetricEncryptionAlgorithm.AES_192.GCM,
                SymmetricEncryptionAlgorithm.AES_256.GCM,
                SymmetricEncryptionAlgorithm.ChaCha20Poly1305
            )
        ) - { alg ->

            data(
                listOf(
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
                    InsecureRandom.nextBytes(21257)
                ), nameFn = { "${it.size} Bytes" }) - { plaintext ->
                val key = runBlocking { alg.randomKey(InsecureRandom) }
                data(
                    listOf(alg.randomNonce(), alg.randomNonce(), null),
                    nameFn = { "IV: " + it?.toHexString()?.substring(0..8) }) - { iv ->

                    data(
                        listOf(InsecureRandom.nextBytes(32), null),
                        nameFn = { "AAD: " + it?.toHexString() }) test { aad ->
                        key.encrypt(plaintext, aad)
                        val ciphertext =
                            if (iv != null) key.andPredefinedNonce(iv).encrypt(plaintext, aad)
                            else key.encrypt(plaintext, aad)

                        ciphertext.nonce.shouldNotBeNull()
                        ciphertext.nonce.size shouldBe alg.nonceSize.bytes.toInt()
                        if (iv != null) ciphertext.nonce shouldBe iv
                        ciphertext.algorithm.authCapability.shouldBeInstanceOf<AuthCapability.Authenticated>()
                        val decrypted = ciphertext.decrypt(key, aad ?: byteArrayOf())
                        decrypted shouldBe plaintext


                        shouldThrowAny { ciphertext.decrypt(alg.randomKey(InsecureRandom)) }

                        val wrongCiphertext = alg.sealedBox.withNonce(ciphertext.nonce).from(
                            InsecureRandom.nextBytes(ciphertext.encryptedData.size),
                            authTag = ciphertext.authTag,
                        )


                        shouldThrowAny { wrongCiphertext.decrypt(alg.randomKey(InsecureRandom), aad ?: byteArrayOf()) }

                        shouldThrowAny { wrongCiphertext.decrypt(key) }

                        val wrongIV = alg.sealedBox.withNonce(ciphertext.nonce.asList().shuffled().toByteArray()).from(
                            ciphertext.encryptedData,
                            authTag = ciphertext.authTag,
                        )

                        shouldThrowAny { wrongIV.decrypt(key, aad ?: byteArrayOf()) }


                        if (aad != null) {
                            val box = alg.sealedBox.withNonce(ciphertext.nonce).from(
                                encryptedData = ciphertext.encryptedData,
                                authTag = ciphertext.authTag,
                            )
                            shouldThrowAny { box.decrypt(key) }
                        }
                        val wrongTag = alg.sealedBox.withNonce(ciphertext.nonce).from(
                            ciphertext.encryptedData,
                            authTag = ciphertext.authTag.asList().shuffled().toByteArray(),
                        )
                        shouldThrowAny { wrongTag.decrypt(key, aad ?: byteArrayOf()) }
                    }
                }
            }
        }
    }

    "CBC+HMAC" - {
        data(
            listOf(
                "Default" to DefaultMacInputCalculation,
                "Oklahoma MAC" to { ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray? ->
                    "Oklahoma".encodeToByteArray() +
                            (iv ?: byteArrayOf()) +
                            (aad ?: byteArrayOf()) +
                            ciphertext
                }), nameFn = { it.first }) - { (_, macInputFun) ->
            data(
                listOf(
                    SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_1.Custom(
                        HMAC.SHA1.outputLength,
                        DefaultMacAuthTagTransformation,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_1.Custom(
                        HMAC.SHA1.outputLength,
                        DefaultMacAuthTagTransformation,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_1.Custom(
                        HMAC.SHA1.outputLength,
                        DefaultMacAuthTagTransformation,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256.Custom(
                        HMAC.SHA256.outputLength,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256.Custom(
                        HMAC.SHA256.outputLength,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256.Custom(
                        HMAC.SHA256.outputLength,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_384.Custom(
                        HMAC.SHA384.outputLength,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384.Custom(
                        HMAC.SHA384.outputLength,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_384.Custom(
                        HMAC.SHA384.outputLength,
                        macInputFun
                    ), SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512.Custom(
                        HMAC.SHA512.outputLength,
                        macInputFun,
                    ), SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512.Custom(
                        HMAC.SHA512.outputLength,
                        macInputFun,
                    ), SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512.Custom(
                        HMAC.SHA512.outputLength,
                        macInputFun,
                    )
                )
            ) - {
                data(
                    listOf(
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
                        InsecureRandom.nextBytes(21257)
                    ), nameFn = { "${it.size} Bytes" }) - { plaintext ->

                    val secretKey = runBlocking { it.randomKey(InsecureRandom).encryptionKey }

                    data(
                        listOf(16, 32, 64, 128, secretKey.size),
                        nameFn = { "MAC KEY $it" }) - { macKeyLen ->

                        val key = runBlocking { it.randomKey(macKeyLen.bytes, InsecureRandom) }

                        data(
                            listOf(
                                InsecureRandom.nextBytes((it.nonceSize.bytes).toInt()),
                                InsecureRandom.nextBytes((it.nonceSize.bytes).toInt()),
                                null
                            ), nameFn = { "IV: " + it?.toHexString()?.substring(0..8) }) - { iv ->
                            data(
                                listOf(InsecureRandom.nextBytes(32), null),
                                nameFn = { "AAD: " + it?.toHexString()?.substring(0..8) }) test { aad ->
                                val ciphertext =
                                    if (iv != null) key.andPredefinedNonce(iv).encrypt(plaintext, aad)
                                    else key.encrypt(plaintext, aad)
                                val manilaAlg = it.Custom(ciphertext.authTag.size.bytes)
                                { _, _, _ -> "Manila".encodeToByteArray() }

                                val manilaKey = SymmetricKey.WithDedicatedMac(
                                    manilaAlg,
                                    key.encryptionKey,
                                    key.macKey
                                )
                                if (iv != null) manilaKey.andPredefinedNonce(iv).encrypt(plaintext, aad) shouldNotBe ciphertext
                                manilaKey.encrypt(plaintext, aad) shouldNotBe ciphertext

                                //no randomness. must be equal
                                val randomIV = it.randomNonce()
                                manilaKey.andPredefinedNonce(randomIV).encrypt(plaintext, aad) shouldBe
                                        manilaKey.andPredefinedNonce(randomIV).encrypt(plaintext, aad)

                                if (iv != null) ciphertext.nonce shouldBe iv
                                ciphertext.nonce.shouldNotBeNull()
                                ciphertext.nonce.size shouldBe it.nonceSize.bytes.toInt()
                                ciphertext.algorithm.authCapability.shouldBeInstanceOf<AuthCapability.Authenticated>()

                                val decrypted = ciphertext.decrypt(key, aad ?: byteArrayOf())
                                decrypted shouldBe plaintext

                                shouldThrowAny { ciphertext.decrypt(it.randomKey(InsecureRandom)) }

                                val wrongCiphertext =
                                    ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                                        InsecureRandom.nextBytes(ciphertext.encryptedData.size),
                                        authTag = ciphertext.authTag,
                                    )

                                shouldThrowAny { wrongCiphertext.decrypt(it.randomKey(InsecureRandom), aad ?: byteArrayOf()) }

                                shouldThrowAny { wrongCiphertext.decrypt(key) }

                                val wrongIV =
                                    ciphertext.algorithm.sealedBox.withNonce(
                                        ciphertext.nonce.asList().shuffled().toByteArray()
                                    ).from(
                                        ciphertext.encryptedData,
                                        ciphertext.authTag,
                                    )

                                shouldThrowAny { wrongIV.decrypt(key, aad ?: byteArrayOf()) }
                                val wrongIVWithTag = ciphertext.algorithm.sealedBox.withNonce(
                                    ciphertext.nonce.asList().shuffled().toByteArray()
                                ).from(
                                    ciphertext.encryptedData,
                                    authTag = ciphertext.authTag,
                                )
                                shouldThrowAny { wrongIVWithTag.decrypt(key, aad ?: byteArrayOf()) }

                                val box = ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                                    ciphertext.encryptedData,
                                    authTag = ciphertext.authTag,
                                )
                                val wrongMacKey = SymmetricKey.WithDedicatedMac(
                                    ciphertext.algorithm,
                                    key.encryptionKey,
                                    dedicatedMacKey = key.macKey.asList().shuffled().toByteArray()
                                )
                                shouldThrowAny { box.decrypt(wrongMacKey, aad ?: byteArrayOf()) }

                                if (aad != null) {
                                    shouldThrowAny { box.decrypt(key) }
                                }

                                val wrongTag = ciphertext.algorithm.sealedBox.withNonce(ciphertext.nonce).from(
                                    ciphertext.encryptedData,
                                    ciphertext.authTag.asList().shuffled().toByteArray(),
                                )
                                shouldThrowAny { wrongTag.decrypt(key, aad ?: byteArrayOf()) }
                                val customAlgorithm = it.Custom(ciphertext.authTag.size.bytes) { _, _, _ ->
                                    "Szombathely".encodeToByteArray()
                                }
                                val customKey = SymmetricKey.WithDedicatedMac(
                                    customAlgorithm, key.encryptionKey, key.macKey
                                )
                                shouldThrowAny { wrongTag.decrypt(customKey, aad ?: byteArrayOf()) }
                            }

                        }
                    }
                }
            }
        }
    }

    "ECB + WRAP" - {
        data(
            listOf(
                SymmetricEncryptionAlgorithm.AES_128.ECB,
                SymmetricEncryptionAlgorithm.AES_192.ECB,
                SymmetricEncryptionAlgorithm.AES_256.ECB,
                SymmetricEncryptionAlgorithm.AES_128.ECB_NOPADDING,
                SymmetricEncryptionAlgorithm.AES_192.ECB_NOPADDING,
                SymmetricEncryptionAlgorithm.AES_256.ECB_NOPADDING,
                SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394,
                SymmetricEncryptionAlgorithm.AES_192.WRAP.RFC3394,
                SymmetricEncryptionAlgorithm.AES_256.WRAP.RFC3394
            )
        ) - { alg ->

            data(
                listOf(
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
                    Random.nextBytes(72)
                ), nameFn = { "data: ${it.size} bytes" }) test { data ->

                val secretKey = alg.randomKey(InsecureRandom)

                //EBC
                if (alg is SymmetricEncryptionAlgorithm.AES.ECB) {

                    val own = secretKey.encrypt(data)


                    own.decrypt(secretKey) shouldBe data

                    //we might get lucky here
                    runCatching { own.decrypt(own.algorithm.randomKey(InsecureRandom)) }.onSuccess {
                        it shouldNotBe data
                    }

                    alg.sealedBox.from(own.encryptedData).decrypt(secretKey) shouldBe data
                } else if (alg is SymmetricEncryptionAlgorithm.AES.ECB_NOPADDING) {
                    if (data.size % AES.blockSize.bytes.toInt() == 0) {

                        val own = secretKey.encrypt(data)


                        own.decrypt(secretKey) shouldBe data

                        //we might get lucky here
                        runCatching { own.decrypt(own.algorithm.randomKey(InsecureRandom)) }.onSuccess {
                            it shouldNotBe data
                        }

                        alg.sealedBox.from(own.encryptedData).decrypt(secretKey) shouldBe data
                    }
                } else {


                    val shouldSucceed = (data.size >= 16) && (data.size % 8 == 0)
                    val trial = runCatching { secretKey.encrypt(data) }

                    trial.isSuccess shouldBe shouldSucceed

                    if (shouldSucceed) {
                        val own = trial.getOrThrow()


                        own.decrypt(secretKey) shouldBe data

                        //we might get lucky here
                        runCatching { own.decrypt(own.algorithm.randomKey(InsecureRandom)) }.onSuccess {
                            it shouldNotBe data
                        }

                        alg.sealedBox.from(own.encryptedData).decrypt(secretKey) shouldBe data
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
        data(allAlgorithms) - { alg ->
            data(
                listOf(//multiples of 8, so AES-KW works
                    Random.nextBytes(192),
                    Random.nextBytes(24),
                    Random.nextBytes(32),
                    Random.nextBytes(56),
                    Random.nextBytes(64),
                    Random.nextBytes(256),
                    Random.nextBytes(1024),
                    Random.nextBytes(4096)
                ), nameFn = { "data: ${it.size} bytes" }) test { plaintext ->
                alg.randomKey(InsecureRandom).also { key ->
                    when (alg.hasDedicatedMac()) {
                        true -> {
                            require(key.hasDedicatedMacKey())
                            key shouldBe alg.keyFrom(
                                key.encryptionKey,
                                key.macKey
                            )

                            key shouldNotBe alg.keyFrom(
                                key.encryptionKey,
                                key.macKey.asList().shuffled()
                                    .toByteArray()
                            )
                            key shouldNotBe alg.keyFrom(
                                key.encryptionKey.asList().shuffled().toByteArray(),
                                key.macKey
                            )
                            key shouldNotBe alg.keyFrom(
                                key.encryptionKey.asList().shuffled().toByteArray(),
                                key.macKey.asList().shuffled()
                                    .toByteArray()
                            )
                        }

                        false -> {
                            require(!key.hasDedicatedMacKey())
                            key shouldBe alg.keyFrom(key.secretKey)
                        }
                    }
                }


                if (alg.isAuthenticated()) {
                    val aad = plaintext.asList().shuffled().toByteArray()
                    if (!alg.requiresNonce()) alg.randomKey(InsecureRandom).let { key ->
                        key.encrypt(plaintext, aad) shouldBe key.encrypt(plaintext, aad)
                        key.encrypt(plaintext, plaintext) shouldNotBe key.encrypt(plaintext, aad)
                    }
                    else alg.randomKey(InsecureRandom).let { key ->

                        key.encrypt(plaintext, aad) shouldNotBe key.encrypt(plaintext, aad)

                        val nonce = alg.randomNonce()
                        key.andPredefinedNonce(nonce)
                            .encrypt(plaintext) shouldBe key.andPredefinedNonce(nonce)
                            .encrypt(plaintext)

                        key.andPredefinedNonce(nonce)
                            .encrypt(plaintext) shouldNotBe key.andPredefinedNonce(alg.randomNonce())
                            .encrypt(plaintext)
                    }
                } else {
                    if (!alg.requiresNonce()) alg.randomKey(InsecureRandom).also { key ->
                        key.encrypt(plaintext) shouldBe key.encrypt(plaintext)
                    } else alg.randomKey(InsecureRandom).let { key ->

                        key.encrypt(plaintext) shouldNotBe key.encrypt(plaintext)

                        val nonce = alg.randomNonce()
                        key.andPredefinedNonce(nonce)
                            .encrypt(plaintext) shouldBe key.andPredefinedNonce(nonce)
                            .encrypt(plaintext)

                        key.andPredefinedNonce(nonce)
                            .encrypt(plaintext) shouldNotBe key.andPredefinedNonce(alg.randomNonce())
                            .encrypt(plaintext)
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
                                        key.encryptionKey,
                                        key.macKey /*size will not match, but it will get us a valid key*/
                                    ) shouldNotBe key
                                }
                            } else if (!wrongAlg.hasDedicatedMac() && !alg.hasDedicatedMac()) {
                                alg.randomKey(InsecureRandom).let { key ->
                                    wrongAlg.keyFrom(
                                        key.secretKey,
                                    ) shouldNotBe key
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
                    }

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
                    }

                    box shouldNotBe box2
                }
            }
        }
    }


    "Edge Cases " - {
        "all good" - {
            data(
                listOf(
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
                    SymmetricEncryptionAlgorithm.AES_256.GCM, /*NO WRAP, because it has constraints on input size*/
                    SymmetricEncryptionAlgorithm.ChaCha20Poly1305
                )
            ) - { alg ->

                data(listOf(0, 1, 4096)) test { sz ->
                    val data = Random.nextBytes(sz)
                    val key = alg.randomKey(InsecureRandom)
                    key.encrypt(data).decrypt(key) shouldBe data
                }
            }
        }

        "algorithm mismatch" - {
            data(allAlgorithms) - { alg ->
                data(allAlgorithms.filterNot { it == alg }) test { wrongAlg ->
                    val encrypted =
                        alg.randomKey(InsecureRandom).encrypt(Random.nextBytes(64)/*works with wrapping*/)
                    val wrongKey = wrongAlg.randomKey(InsecureRandom)

                    shouldThrow<IllegalArgumentException> { encrypted.decrypt(wrongKey) }

                }
            }
        }
        "illegal key sizes" - {
            data(allAlgorithms) - { alg ->
                val wrongSized = mutableListOf<Int>()
                while (wrongSized.size < 100) {
                    val wrong = Random.nextUInt(until = 1025u).toInt()
                    if (wrong != alg.keySize.bytes.toInt())
                        wrongSized += wrong
                }
                data(wrongSized) test { sz ->
                    shouldThrow<IllegalArgumentException> {
                        when (alg.hasDedicatedMac()) {
                            true -> {
                                alg.keyFrom(
                                    Random.nextBytes(sz),
                                    alg.randomKey(InsecureRandom).encryptionKey /*mac key should not trigger, as it is unconstrained*/
                                )
                            }

                            false -> {
                                alg.keyFrom(Random.nextBytes(sz))
                            }
                        }
                    }
                }
            }
        }

        "illegal nonce sizes" - {
            data(allAlgorithms.mapNotNull { if (it.requiresNonce()) it else null }) - { alg ->
                val wrongSized = mutableListOf<Int>()
                while (wrongSized.size < 100) {
                    val wrong = Random.nextUInt(until = 1025u).toInt()
                    if (wrong != alg.nonceSize.bytes.toInt())
                        wrongSized += wrong
                }
                data(wrongSized) test { sz ->
                    shouldThrow<IllegalArgumentException> { alg.randomKey(InsecureRandom).andPredefinedNonce(Random.nextBytes(sz)) }
                }

            }
        }
    }
}

