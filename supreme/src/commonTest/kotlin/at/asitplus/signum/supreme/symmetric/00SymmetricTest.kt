import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.succeed
import at.asitplus.signum.supreme.symmetric.*
import at.asitplus.signum.supreme.symmetric.discouraged.andPredefinedNonce
import at.asitplus.signum.supreme.symmetric.discouraged.encrypt
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
import org.kotlincrypto.SecureRandom
import kotlin.random.Random

@OptIn(HazardousMaterials::class)
@ExperimentalStdlibApi
class `0SymmetricTest` : FreeSpec({


    "Illegal IV Size" - {
        withData(
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
                Random.nextBytes(0),
                Random.nextBytes(1),
                Random.nextBytes(17),
                Random.nextBytes(18),
                Random.nextBytes(33),
                Random.nextBytes(256),
                null
            ) { iv ->

                val key = alg.randomKey()
                if (iv != null) key.andPredefinedNonce(iv) shouldNot succeed
                else key.encrypt(Random.nextBytes(32)) should succeed
                key.andPredefinedNonce(alg.randomNonce()).getOrThrow().encrypt(Random.nextBytes(32)) should succeed
                key.encrypt(Random.nextBytes(32)) should succeed

                if (alg.authCapability is AuthType.Authenticated)
                    key.encrypt(Random.nextBytes(32))
                        .getOrThrow().algorithm.isAuthenticated() shouldBe true
                else if (alg.authCapability is AuthType.Unauthenticated)
                    key.encrypt(Random.nextBytes(32))
                        .getOrThrow().algorithm.isAuthenticated() shouldBe false
            }
        }
    }


    "Illegal Key Size" - {
        withData(
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

               when(alg.hasDedicatedMac()) {
                    true -> alg.keyFrom(keyBytes,keyBytes) //never do this in production!
                    false -> alg.keyFrom(keyBytes)
                } shouldNot succeed

               val key =  when(alg.hasDedicatedMac()) {
                    true -> alg.keyFrom(alg.randomKey().secretKey, alg.randomKey().secretKey)
                    false -> alg.keyFrom(alg.randomKey().secretKey)
                }.getOrThrow()



                key.encrypt(Random.nextBytes(32)) should succeed
                key.andPredefinedNonce(alg.randomNonce()).getOrThrow().encrypt(data = Random.nextBytes(32)) should succeed

                if (alg.authCapability is AuthType.Authenticated)
                    alg.randomKey().encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it should succeed
                        it.getOrThrow().algorithm.isAuthenticated() shouldBe true
                    }
                else if (alg.authCapability is AuthType.Unauthenticated)
                    alg.randomKey().encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it should succeed
                        it.getOrThrow().algorithm.isAuthenticated() shouldBe false
                    }
            }
        }
    }

    "CBC.PLAIN" - {

        withData(
            SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
            SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN,
        ) {
            withData(
                nameFn = { "${it.size} Bytes" },
                Random.Default.nextBytes(5),
                Random.Default.nextBytes(15),
                Random.Default.nextBytes(16),
                Random.Default.nextBytes(17),
                Random.Default.nextBytes(31),
                Random.Default.nextBytes(32),
                Random.Default.nextBytes(33),
                Random.Default.nextBytes(256),
                Random.Default.nextBytes(257),
                Random.Default.nextBytes(1257),
                Random.Default.nextBytes(21257),
            ) { plaintext ->

                val key = it.randomKey()

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
                    ciphertext.nonce.size shouldBe it.nonce.length.bytes.toInt()
                    iv?.let { ciphertext.nonce shouldBe iv }
                    ciphertext.algorithm.isAuthenticated() shouldBe false


                    val decrypted = ciphertext.decrypt(key).getOrThrow()
                    decrypted shouldBe plaintext


                    val wrongDecrypted = ciphertext.decrypt(it.randomKey())
                    //We're not authenticated, so from time to time, we won't run into a padding error for specific plaintext sizes
                    wrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }

                    val wrongCiphertext =
                        ciphertext.algorithm.sealedBox(
                            ciphertext.nonce,
                            Random.Default.nextBytes(ciphertext.encryptedData.size)
                        ).getOrThrow()

                    val wrongWrongDecrypted = wrongCiphertext.decrypt(it.randomKey())
                    withClue("KEY: ${key.secretKey.toHexString()}, wrongCiphertext: ${wrongCiphertext.encryptedData.toHexString()}, ciphertext: ${ciphertext.encryptedData.toHexString()}, iv: ${wrongCiphertext.nonce?.toHexString()}") {
                        //we're not authenticated, so from time to time, this succeeds
                        //wrongWrongDecrypted shouldNot succeed
                        //instead, we test differently:
                        wrongWrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }
                    }
                    val wrongRightDecrypted = wrongCiphertext.decrypt(key)
                    withClue("KEY: ${key.secretKey.toHexString()}, wrongCiphertext: ${wrongCiphertext.encryptedData.toHexString()}, ciphertext: ${ciphertext.encryptedData.toHexString()}, iv: ${wrongCiphertext.nonce?.toHexString()}") {
                        //we're not authenticated, so from time to time, this succeeds
                        //wrongRightDecrypted shouldNot succeed
                        //instead, we test differently:
                        wrongRightDecrypted.onSuccess { value -> value shouldNotBe plaintext }
                    }
                    val wrongIV =
                        ciphertext.algorithm.sealedBox(
                            nonce = ciphertext.nonce.asList().shuffled().toByteArray(),
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
        withData(
            SymmetricEncryptionAlgorithm.AES_128.GCM,
            SymmetricEncryptionAlgorithm.AES_192.GCM,
            SymmetricEncryptionAlgorithm.AES_256.GCM,

            SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        ) { alg ->

            withData(
                nameFn = { "${it.size} Bytes" },
                Random.Default.nextBytes(5),
                Random.Default.nextBytes(15),
                Random.Default.nextBytes(16),
                Random.Default.nextBytes(17),
                Random.Default.nextBytes(31),
                Random.Default.nextBytes(32),
                Random.Default.nextBytes(33),
                Random.Default.nextBytes(256),
                Random.Default.nextBytes(257),
                Random.Default.nextBytes(1257),
                Random.Default.nextBytes(21257),
            ) { plaintext ->
                val key = alg.randomKey()
                withData(
                    nameFn = { "IV: " + it?.toHexString()?.substring(0..8) },
                    alg.randomNonce(),
                    alg.randomNonce(),
                    null
                ) { iv ->

                    withData(
                        nameFn = { "AAD: " + it?.toHexString() },
                        Random.Default.nextBytes(32),
                        null
                    ) { aad ->
                        key.encrypt(plaintext, aad)
                        val ciphertext =
                            if (iv != null) key.andPredefinedNonce(iv).getOrThrow().encrypt(plaintext, aad).getOrThrow()
                            else key.encrypt(plaintext, aad).getOrThrow()

                        ciphertext.nonce.shouldNotBeNull()
                        ciphertext.nonce.size shouldBe alg.nonce.length.bytes.toInt()
                        if (iv != null) ciphertext.nonce shouldBe iv
                        ciphertext.algorithm.authCapability.shouldBeInstanceOf<AuthType.Authenticated<*>>()
                        ciphertext.authenticatedData shouldBe aad

                        val decrypted = ciphertext.decrypt(key).getOrThrow()
                        decrypted shouldBe plaintext


                        val wrongDecrypted = ciphertext.decrypt(alg.randomKey())
                        wrongDecrypted shouldNot succeed

                        val wrongCiphertext = alg.sealedBox(
                            ciphertext.nonce,
                            Random.Default.nextBytes(ciphertext.encryptedData.size),
                            authTag = ciphertext.authTag,
                            authenticatedData = ciphertext.authenticatedData
                        ).getOrThrow()


                        val wrongWrongDecrypted = wrongCiphertext.decrypt(alg.randomKey())
                        wrongWrongDecrypted shouldNot succeed

                        val wrongRightDecrypted = wrongCiphertext.decrypt(key)
                        wrongRightDecrypted shouldNot succeed

                        val wrongIV = alg.sealedBox(
                            nonce = ciphertext.nonce.asList().shuffled().toByteArray(),
                            ciphertext.encryptedData,
                            authTag = ciphertext.authTag,
                            authenticatedData = ciphertext.authenticatedData
                        ).getOrThrow()

                        val wrongIVDecrypted = wrongIV.decrypt(key)
                        wrongIVDecrypted shouldNot succeed


                        if (aad != null) {
                            //missing aad
                            alg.sealedBox(
                                nonce = ciphertext.nonce,
                                encryptedData = ciphertext.encryptedData,
                                authTag = ciphertext.authTag,
                                authenticatedData = null
                            ).getOrThrow().decrypt(key) shouldNot succeed

                        }
                        //shuffled auth tag
                        alg.sealedBox(
                            nonce = ciphertext.nonce,
                            ciphertext.encryptedData,
                            authTag = ciphertext.authTag.asList().shuffled().toByteArray(),
                            authenticatedData = ciphertext.authenticatedData,
                        ).getOrThrow().decrypt(key) shouldNot succeed
                    }
                }
            }
        }
    }

    "CBC+HMAC" - {
        withData(
            nameFn = { it.first },
            "Default" to DefaultDedicatedMacInputCalculation,
            "Oklahoma MAC" to fun MAC.(ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray?): ByteArray =
                "Oklahoma".encodeToByteArray() + (iv ?: byteArrayOf()) + (aad
                    ?: byteArrayOf()) + ciphertext) { (_, macInputFun) ->
            withData(
                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_1.Custom(macInputFun),
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_1.Custom(macInputFun),
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_1.Custom(macInputFun),


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256.Custom(macInputFun),
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256.Custom(macInputFun),
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256.Custom(macInputFun),


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_384.Custom(macInputFun),
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384.Custom(macInputFun),
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_384.Custom(macInputFun),


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512.Custom(macInputFun),
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512.Custom(macInputFun),
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512.Custom(macInputFun),
            ) {
                withData(
                    nameFn = { "${it.size} Bytes" },
                    Random.Default.nextBytes(16),
                    byteArrayOf(),
                    Random.Default.nextBytes(5),
                    Random.Default.nextBytes(15),
                    Random.Default.nextBytes(17),
                    Random.Default.nextBytes(31),
                    Random.Default.nextBytes(32),
                    Random.Default.nextBytes(33),
                    Random.Default.nextBytes(256),
                    Random.Default.nextBytes(257),
                    Random.Default.nextBytes(1257),
                    Random.Default.nextBytes(21257),
                ) { plaintext ->

                    val secretKey = it.randomKey().secretKey

                    withData(
                        nameFn = { "MAC KEY $it" },
                        16, 32, 64, 128, secretKey.size
                    ) { macKeyLen ->

                        val key = it.randomKey(macKeyLen.bytes)

                        withData(
                            nameFn = { "IV: " + it?.toHexString()?.substring(0..8) },
                            Random.Default.nextBytes((it.nonce.length.bytes).toInt()),
                            Random.Default.nextBytes((it.nonce.length.bytes).toInt()),
                            null
                        ) { iv ->
                            withData(
                                nameFn = { "AAD: " + it?.toHexString()?.substring(0..8) },
                                Random.Default.nextBytes(32),
                                null
                            ) { aad ->
                                val ciphertext =
                                    if (iv != null) key.andPredefinedNonce(iv).getOrThrow().encrypt(plaintext, aad).getOrThrow()
                                    else key.encrypt(plaintext, aad).getOrThrow()
                                val manilaAlg = it.Custom { _, _, _ -> "Manila".encodeToByteArray() }
                                val manilaKey = SymmetricKey.WithDedicatedMac.RequiringNonce(
                                    manilaAlg,
                                    key.secretKey,
                                    key.dedicatedMacKey
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
                                ciphertext.nonce.size shouldBe it.nonce.length.bytes.toInt()
                                ciphertext.algorithm.authCapability.shouldBeInstanceOf<AuthType.Authenticated<*>>()
                                ciphertext.authenticatedData shouldBe aad

                                val decrypted = ciphertext.decrypt(key).getOrThrow()
                                decrypted shouldBe plaintext

                                val wrongDecrypted = ciphertext.decrypt(it.randomKey())
                                wrongDecrypted shouldNot succeed

                                val wrongCiphertext =
                                    ciphertext.algorithm.sealedBox(
                                        ciphertext.nonce,
                                        Random.Default.nextBytes(ciphertext.encryptedData.size),
                                        authTag = ciphertext.authTag,
                                        authenticatedData = ciphertext.authenticatedData
                                    ).getOrThrow()

                                val wrongWrongDecrypted = wrongCiphertext.decrypt(it.randomKey())
                                wrongWrongDecrypted shouldNot succeed

                                val wrongRightDecrypted =
                                    wrongCiphertext.decrypt(key)
                                wrongRightDecrypted shouldNot succeed

                                val wrongIV =
                                    ciphertext.algorithm.sealedBox(
                                        nonce = ciphertext.nonce.asList().shuffled().toByteArray(),
                                        ciphertext.encryptedData,
                                        ciphertext.authTag,
                                        ciphertext.authenticatedData
                                    ).getOrThrow()

                                val wrongIVDecrypted = wrongIV.decrypt(key)
                                wrongIVDecrypted shouldNot succeed
                                ciphertext.algorithm.sealedBox(
                                    nonce = ciphertext.nonce.asList().shuffled().toByteArray(),
                                    ciphertext.encryptedData,
                                    authTag = ciphertext.authTag,
                                    authenticatedData = ciphertext.authenticatedData,
                                ).getOrThrow().decrypt(key) shouldNot succeed

                                ciphertext.algorithm.sealedBox(
                                    nonce = ciphertext.nonce,
                                    ciphertext.encryptedData,
                                    authTag = ciphertext.authTag,
                                    authenticatedData = ciphertext.authenticatedData,
                                ).getOrThrow().decrypt(
                                    SymmetricKey.WithDedicatedMac.RequiringNonce(
                                        ciphertext.algorithm as SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required, KeyType.WithDedicatedMacKey>,
                                        key.secretKey,
                                        dedicatedMacKey = key.dedicatedMacKey.asList().shuffled().toByteArray()
                                    )
                                ) shouldNot succeed

                                if (aad != null) {
                                    ciphertext.algorithm.sealedBox(
                                        ciphertext.nonce,
                                        ciphertext.encryptedData,
                                        ciphertext.authTag,
                                        null
                                    ).getOrThrow().decrypt(key) shouldNot succeed
                                }

                                ciphertext.algorithm.sealedBox(
                                    ciphertext.nonce,
                                    ciphertext.encryptedData,
                                    ciphertext.authTag.asList().shuffled().toByteArray(),
                                    ciphertext.authenticatedData
                                ).getOrThrow().decrypt(key) shouldNot succeed
                                ciphertext.algorithm.sealedBox(
                                    ciphertext.nonce,
                                    ciphertext.encryptedData,
                                    ciphertext.authTag.asList().shuffled().toByteArray(),
                                    ciphertext.authenticatedData
                                ).getOrThrow().decrypt(it.Custom { _, _, _ ->
                                    "Szombathely".encodeToByteArray()
                                }.let {
                                    SymmetricKey.WithDedicatedMac.RequiringNonce(
                                        it,
                                        key.secretKey,
                                        key.dedicatedMacKey
                                    )
                                }) shouldNot succeed
                            }

                        }
                    }
                }
            }
        }
    }

    "ECB + WRAP" - {
        withData(

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

                val secretKey = alg.randomKey()

                //CBC
                if (alg !is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394) {

                    val own = secretKey.encrypt(data).getOrThrow()


                    own.decrypt(secretKey).getOrThrow() shouldBe data

                    //we might get lucky here
                    own.decrypt(own.algorithm.randomKey()).onSuccess {
                        it shouldNotBe data
                    }

                    alg.sealedBox(own.encryptedData).getOrThrow().decrypt(secretKey) should succeed
                } else {


                    val shouldSucceed = (data.size >= 16) && (data.size % 8 == 0)
                    val trial = secretKey.encrypt(data)

                    if (shouldSucceed)
                        trial should succeed
                    else trial shouldNot succeed




                    if (shouldSucceed) {
                        val own = trial.getOrThrow()


                        own.decrypt(secretKey).getOrThrow() shouldBe data

                        //we might get lucky here
                        own.decrypt(own.algorithm.randomKey()).onSuccess {
                            it shouldNotBe data
                        }

                        alg.sealedBox(own.encryptedData).getOrThrow().decrypt(secretKey) should succeed
                    }
                }
            }
        }
    }

    "README" {
        val secureRandom = SecureRandom()

        val payload = "More matter, with less art!".encodeToByteArray()

        //define algorithm parameters
        val algorithm = SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512
            //with a custom HMAC input calculation function
            .Custom { ciphertext, iv, aad -> //A shorter version of RFC 7518
                aad + iv + ciphertext + aad.size.encodeTo4Bytes()
            }

        //any size is fine, really. omitting the override generates a mac key of the same size as the encryption key
        val key = algorithm.randomKey(macKeyLength = 32.bit)
        val aad = Clock.System.now().toString().encodeToByteArray()

        val sealedBox = key.encrypt(
            payload,
            authenticatedData = aad,
        ).getOrThrow(/*handle error*/)

        //The sealed box object is correctly typed:
        //  * It is a SealedBox.WithIV
        //  * The generic type arguments indicate that
        //      * the ciphertext is authenticated
        //      * Using a dedicated MAC function atop an unauthenticated cipher
        //  * we can hence access `authenticatedCiphertext` for:
        //      * authTag
        //      * authenticatedData
        sealedBox.authenticatedData shouldBe aad

        //because everything is structured, decryption is simple
        val recovered = sealedBox.decrypt(key).getOrThrow(/*handle error*/)

        recovered shouldBe payload //success!

        //we can also manually construct the sealed box, if we know the algorithm:
        val reconstructed = algorithm.sealedBox(
            sealedBox.nonce,
            encryptedData = sealedBox.encryptedData, /*Could also access authenticatedCipherText*/
            authTag = sealedBox.authTag,
            authenticatedData = sealedBox.authenticatedData
        ).getOrThrow()

        val manuallyRecovered = reconstructed.decrypt(
            key
        ).getOrThrow(/*handle error*/)

        manuallyRecovered shouldBe payload //great success!

        //if we just know algorithm and key bytes, we can also construct a symmetric key
        reconstructed.decrypt(
            algorithm.keyFrom(key.secretKey, key.dedicatedMacKey).getOrThrow(/*handle error*/),
        ).getOrThrow(/*handle error*/) shouldBe payload //greatest success!
    }
})

