import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes
import at.asitplus.signum.indispensable.mac.MAC
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
class SymmetricTest : FreeSpec({


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
                Random.nextBytes(32),
                Random.nextBytes(256),
                null
            ) { iv ->

                val key = alg.randomKey()
                if (iv != null) key.andPredefinedNonce(iv).encrypt(Random.nextBytes(32)) shouldNot succeed
                else key.encrypt(Random.nextBytes(32)) should succeed
                key.andPredefinedNonce(alg.randomNonce()).encrypt(Random.nextBytes(32)) should succeed
                key.encrypt(Random.nextBytes(32)) should succeed
                if (alg.cipher is AECapability.Authenticated)
                    key.encrypt(Random.nextBytes(32))
                        .getOrThrow().cipherKind.shouldBeInstanceOf<AECapability.Authenticated>()
                else if (alg.cipher is AECapability.Unauthenticated)
                    key.encrypt(Random.nextBytes(32))
                        .getOrThrow().cipherKind.shouldBeInstanceOf<AECapability.Unauthenticated>()
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

                //prohibited!
                alg.keyFrom(keyBytes) shouldNot succeed

                //so we try to out-smart ourselves and it must fail later on
                val key = (when (alg.randomKey()) {
                    //Covers Unauthenticated and GCM
                    is SymmetricKey.Integrated<*, Nonce.Required> -> SymmetricKey.Integrated(alg, keyBytes)
                    is SymmetricKey.WithDedicatedMac<Nonce.Required> -> SymmetricKey.WithDedicatedMac(
                        alg as SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, *>, Nonce.Required>,
                        keyBytes
                    )
                })


                key.encrypt(Random.nextBytes(32)) shouldNot succeed
                key.andPredefinedNonce(alg.randomNonce()).encrypt(data = Random.nextBytes(32)) shouldNot succeed

                if (alg.cipher is AECapability.Authenticated)
                    alg.randomKey().encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it should succeed
                        it.getOrThrow().cipherKind.shouldBeInstanceOf<AECapability.Authenticated>()
                    }
                else if (alg.cipher is AECapability.Unauthenticated)
                    alg.randomKey().encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it should succeed
                        it.getOrThrow().cipherKind.shouldBeInstanceOf<AECapability.Unauthenticated>()
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
                        if (iv != null) key.andPredefinedNonce(iv).encrypt(plaintext).getOrThrow()
                        else key.encrypt(plaintext).getOrThrow()

                    ciphertext.nonce.shouldNotBeNull()
                    if (iv != null) ciphertext.nonce.size shouldBe iv.size
                    ciphertext.nonce.size shouldBe it.nonce.length.bytes.toInt()
                    iv?.let { ciphertext.nonce shouldBe iv }
                    ciphertext.cipherKind.shouldBeInstanceOf<AECapability.Unauthenticated>()


                    val decrypted = ciphertext.decrypt(key).getOrThrow()
                    decrypted shouldBe plaintext


                    val wrongDecrypted = ciphertext.decrypt(it.randomKey())
                    //We're not authenticated, so from time to time, we won't run into a padding error for specific plaintext sizes
                    wrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }

                    val wrongCiphertext =
                        ciphertext.algorithm.sealedBox(
                            ciphertext.nonce,
                            Random.Default.nextBytes(ciphertext.encryptedData.size)
                        )

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
                        )


                    if (plaintext.size > it.blockSize.bytes.toInt()) { //cannot test like that for ciphertexts shorter than IV
                        val wrongIVDecrypted = wrongIV.decrypt(key)
                        wrongIVDecrypted should succeed
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

                        val ciphertext =
                            if (iv != null) key.andPredefinedNonce(iv).encrypt(plaintext, aad).getOrThrow()
                            else key.encrypt(plaintext, aad).getOrThrow()

                        ciphertext.nonce.shouldNotBeNull()
                        ciphertext.nonce.size shouldBe alg.nonce.length.bytes.toInt()
                        if (iv != null) ciphertext.nonce shouldBe iv
                        ciphertext.cipherKind.shouldBeInstanceOf<AECapability.Authenticated>()
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
                        )


                        val wrongWrongDecrypted = wrongCiphertext.decrypt(alg.randomKey())
                        wrongWrongDecrypted shouldNot succeed

                        val wrongRightDecrypted = wrongCiphertext.decrypt(key)
                        wrongRightDecrypted shouldNot succeed

                        val wrongIV = alg.sealedBox(
                            nonce = ciphertext.nonce.asList().shuffled().toByteArray(),
                            ciphertext.encryptedData,
                            authTag = ciphertext.authTag,
                            authenticatedData = ciphertext.authenticatedData
                        )

                        val wrongIVDecrypted = wrongIV.decrypt(key)
                        wrongIVDecrypted shouldNot succeed


                        if (aad != null) {
                            //missing aad
                            alg.sealedBox(
                                nonce = ciphertext.nonce,
                                encryptedData = ciphertext.encryptedData,
                                authTag = ciphertext.authTag,
                                authenticatedData = null
                            ).decrypt(key) shouldNot succeed

                        }
                        //shuffled auth tag
                        alg.sealedBox(
                            nonce = ciphertext.nonce,
                            ciphertext.encryptedData,
                            authTag = ciphertext.authTag.asList().shuffled().toByteArray(),
                            authenticatedData = ciphertext.authenticatedData,
                        ).decrypt(key) shouldNot succeed
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
                    byteArrayOf(),
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

                    val secretKey = it.randomKey().secretKey

                    withData(
                        nameFn = { "MAC KEY " + it.toHexString().substring(0..8) },
                        Random.Default.nextBytes(8),
                        Random.Default.nextBytes(16),
                        Random.Default.nextBytes(32),
                        secretKey
                    ) { macKey ->

                        val key = it.randomKey(macKey)

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
                                    if (iv != null) key.andPredefinedNonce(iv).encrypt(plaintext, aad).getOrThrow()
                                    else key.encrypt(plaintext, aad).getOrThrow()
                                val manilaAlg = it.Custom { _, _, _ -> "Manila".encodeToByteArray() }
                                val manilaKey = SymmetricKey.WithDedicatedMac<Nonce.Required>(
                                    manilaAlg,
                                    key.secretKey,
                                    key.dedicatedMacKey
                                )
                                if (iv != null) manilaKey.andPredefinedNonce(iv).encrypt(plaintext, aad)
                                    .getOrThrow() shouldNotBe ciphertext
                                manilaKey.encrypt(plaintext, aad).getOrThrow() shouldNotBe ciphertext

                                //no randomness. must be equal
                                val randomIV = it.randomNonce()
                                manilaKey.andPredefinedNonce(randomIV).encrypt(plaintext, aad)
                                    .getOrThrow() shouldBe
                                        manilaKey.andPredefinedNonce(randomIV).encrypt(plaintext, aad)
                                            .getOrThrow()

                                if (iv != null) ciphertext.nonce shouldBe iv
                                ciphertext.nonce.shouldNotBeNull()
                                ciphertext.nonce.size shouldBe it.nonce.length.bytes.toInt()
                                ciphertext.cipherKind.shouldBeInstanceOf<AECapability.Authenticated>()
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
                                    )

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
                                    )

                                val wrongIVDecrypted = wrongIV.decrypt(key)
                                wrongIVDecrypted shouldNot succeed
                                ciphertext.algorithm.sealedBox(
                                    nonce = ciphertext.nonce.asList().shuffled().toByteArray(),
                                    ciphertext.encryptedData,
                                    authTag = ciphertext.authTag,
                                    authenticatedData = ciphertext.authenticatedData,
                                ).decrypt(key) shouldNot succeed

                                ciphertext.algorithm.sealedBox(
                                    nonce = ciphertext.nonce,
                                    ciphertext.encryptedData,
                                    authTag = ciphertext.authTag,
                                    authenticatedData = ciphertext.authenticatedData,
                                ).decrypt(
                                    SymmetricKey.WithDedicatedMac<Nonce.Required>(
                                        ciphertext.algorithm,
                                        key.secretKey,
                                        dedicatedMacKey = macKey.asList().shuffled().toByteArray()
                                    )
                                ) shouldNot succeed

                                if (aad != null) {
                                    ciphertext.algorithm.sealedBox(
                                        ciphertext.nonce,
                                        ciphertext.encryptedData,
                                        ciphertext.authTag,
                                        null
                                    ).decrypt(key) shouldNot succeed
                                }

                                ciphertext.algorithm.sealedBox(
                                    ciphertext.nonce,
                                    ciphertext.encryptedData,
                                    ciphertext.authTag.asList().shuffled().toByteArray(),
                                    ciphertext.authenticatedData
                                ).decrypt(key) shouldNot succeed
                                ciphertext.algorithm.sealedBox(
                                    ciphertext.nonce,
                                    ciphertext.encryptedData,
                                    ciphertext.authTag.asList().shuffled().toByteArray(),
                                    ciphertext.authenticatedData
                                ).decrypt(it.Custom { _, _, _ ->
                                    "Szombathely".encodeToByteArray()
                                }.let {
                                    SymmetricKey.WithDedicatedMac<Nonce.Required>(
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

    "README" {
        val secureRandom = SecureRandom()

        val payload = "More matter, with less art!".encodeToByteArray()

        //define algorithm parameters
        val algorithm = SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512
            //with a custom HMAC input calculation function
            .Custom { ciphertext, _, aad -> //A shorter version of per RFC 7518
                (aad ?: byteArrayOf()) + ciphertext + (aad?.size?.encodeTo4Bytes() ?: byteArrayOf())
            }

        //any size is fine, really. omitting the override just uses the encryption key as mac key
        val key = algorithm.randomKey(dedicatedMacKeyOverride = secureRandom.nextBytesOf(32))
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
        )

        val manuallyRecovered = reconstructed.decrypt(
            key,
        ).getOrThrow(/*handle error*/)

        manuallyRecovered shouldBe payload //great success!

        //if we just know algorithm and key bytes, we can also construct a symmetric key
        reconstructed.decrypt(
            algorithm.keyFrom(key.secretKey, key.dedicatedMacKey).getOrThrow(/*handle error*/),
        ).getOrThrow(/*handle error*/) shouldBe payload //greatest success!
    }
})