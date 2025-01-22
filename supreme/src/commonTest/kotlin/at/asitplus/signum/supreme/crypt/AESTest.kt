import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.supreme.crypt.*
import at.asitplus.signum.supreme.succeed
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
import kotlin.random.Random

@OptIn(HazardousMaterials::class)
@ExperimentalStdlibApi
class AESTest : FreeSpec({


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

            ) { alg ->

            withData(
                nameFn = { "${it.size} Bytes" },
                Random.nextBytes(0),
                Random.nextBytes(1),
                Random.nextBytes(17),
                Random.nextBytes(18),
                Random.nextBytes(32),
                Random.nextBytes(256),

                ) { iv ->

                val key =
                    (alg).randomKey()
                key.encrypt(iv, Random.nextBytes(32)) shouldNot succeed
                key.encrypt(alg.randomIV(), Random.nextBytes(32)) should succeed
                key.encrypt(Random.nextBytes(32)) should succeed
                if (alg.cipher is CipherKind.Authenticated)
                    key.encrypt(Random.nextBytes(32)).getOrThrow().ciphertext
                        .shouldBeInstanceOf<Ciphertext.Authenticated<*, *>>()
                else if (alg.cipher is CipherKind.Unauthenticated)
                    key.encrypt(Random.nextBytes(32)).getOrThrow().ciphertext
                        .shouldBeInstanceOf<Ciphertext.Unauthenticated>()
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
                val key = (when (alg.randomKey()) {
                    //Covers Unauthenticated and GCM
                    is SymmetricKey.Integrated<*, IV.Required> -> SymmetricKey.Integrated(alg, keyBytes)
                    is SymmetricKey.WithDedicatedMac<IV.Required> -> SymmetricKey.WithDedicatedMac(
                        alg as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, IV.Required>,
                        keyBytes
                    )
                })



                key.encrypt(Random.nextBytes(32)) shouldNot succeed
                key.encrypt(iv = alg.randomIV(), data = Random.nextBytes(32)) shouldNot succeed

                if (alg.cipher is CipherKind.Authenticated)
                    alg.randomKey().encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it should succeed
                        it.getOrThrow().ciphertext.shouldBeInstanceOf<Ciphertext.Authenticated<*, *>>()
                    }
                else if (alg.cipher is CipherKind.Unauthenticated)
                    alg.randomKey().encrypt(
                        Random.nextBytes(32)
                    ).let {
                        it should succeed
                        it.getOrThrow().ciphertext.shouldBeInstanceOf<Ciphertext.Unauthenticated>()
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
                    nameFn = { "IV: " + it.toHexString().substring(0..8) },
                    it.randomIV(),
                    it.randomIV(),
                ) { iv ->


                    val ciphertext = key.encrypt(iv, plaintext).getOrThrow()



                    ciphertext.iv.shouldNotBeNull()
                    ciphertext.iv.size shouldBe iv.size
                    iv.let { ciphertext.iv shouldBe it }
                    ciphertext.ciphertext.shouldBeInstanceOf<Ciphertext.Unauthenticated>()


                    val decrypted = ciphertext.decrypt(key).getOrThrow()
                    decrypted shouldBe plaintext


                    val wrongDecrypted = ciphertext.decrypt(it.randomKey())
                    //We're not authenticated, so from time to time, we won't run into a padding error for specific plaintext sizes
                    wrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }

                    val wrongCiphertext =
                        ciphertext.ciphertext.algorithm.sealedBox(
                            ciphertext.iv,
                            Random.Default.nextBytes(ciphertext.ciphertext.encryptedData.size)
                        )

                    val wrongWrongDecrypted = wrongCiphertext.decrypt(it.randomKey())
                    withClue("KEY: ${key.secretKey.toHexString()}, wrongCiphertext: ${wrongCiphertext.ciphertext.encryptedData.toHexString()}, ciphertext: ${ciphertext.ciphertext.encryptedData.toHexString()}, iv: ${wrongCiphertext.iv?.toHexString()}") {
                        //we're not authenticated, so from time to time, this succeeds
                        //wrongWrongDecrypted shouldNot succeed
                        //instead, we test differently:
                        wrongWrongDecrypted.onSuccess { value -> value shouldNotBe plaintext }
                    }
                    val wrongRightDecrypted = wrongCiphertext.decrypt(key)
                    withClue("KEY: ${key.secretKey.toHexString()}, wrongCiphertext: ${wrongCiphertext.ciphertext.encryptedData.toHexString()}, ciphertext: ${ciphertext.ciphertext.encryptedData.toHexString()}, iv: ${wrongCiphertext.iv?.toHexString()}") {
                        //we're not authenticated, so from time to time, this succeeds
                        //wrongRightDecrypted shouldNot succeed
                        //instead, we test differently:
                        wrongRightDecrypted.onSuccess { value -> value shouldNotBe plaintext }
                    }
                    val wrongIV =
                        ciphertext.ciphertext.algorithm.sealedBox(
                            iv = ciphertext.iv.asList().shuffled().toByteArray(),
                            encryptedBytes = ciphertext.ciphertext.encryptedData
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

    "GCM" - {
        withData(
            SymmetricEncryptionAlgorithm.AES_128.GCM,
            SymmetricEncryptionAlgorithm.AES_192.GCM,
            SymmetricEncryptionAlgorithm.AES_256.GCM
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
                val key = (alg).randomKey()
                withData(
                    nameFn = { "IV: " + it?.toHexString()?.substring(0..8) },
                    alg.randomIV(),
                    alg.randomIV(),
                ) { iv ->

                    withData(
                        nameFn = { "AAD: " + it?.toHexString() },
                        Random.Default.nextBytes(32),
                        null
                    ) { aad ->

                        val ciphertext =
                            key.encrypt(iv, plaintext, aad).getOrThrow()

                        ciphertext.iv.shouldNotBeNull()
                        ciphertext.iv.size shouldBe alg.iv.ivLen.bytes.toInt()
                        ciphertext.iv shouldBe iv
                        ciphertext.ciphertext.shouldBeInstanceOf<Ciphertext.Authenticated<*, *>>()
                        ciphertext.authenticatedCiphertext.authenticatedData shouldBe aad

                        val decrypted = ciphertext.decrypt(key).getOrThrow()
                        decrypted shouldBe plaintext


                        val wrongDecrypted = ciphertext.decrypt(alg.randomKey().secretKey)
                        wrongDecrypted shouldNot succeed

                        val wrongCiphertext =
                            SealedBox.WithIV<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>(
                                iv = ciphertext.iv,
                                Ciphertext.Authenticated.Integrated(
                                    ciphertext.ciphertext.algorithm as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>,
                                    Random.Default.nextBytes(ciphertext.ciphertext.encryptedData.size),
                                    authTag = ciphertext.authenticatedCiphertext.authTag,
                                    aad = ciphertext.authenticatedCiphertext.authenticatedData,
                                ) as Ciphertext<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>
                            )

                        val wrongWrongDecrypted = wrongCiphertext.decrypt(alg.randomKey().secretKey)
                        wrongWrongDecrypted shouldNot succeed

                        val wrongRightDecrypted = wrongCiphertext.decrypt(key)
                        wrongRightDecrypted shouldNot succeed

                        val wrongIV =
                            SealedBox.WithIV<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>(
                                iv = ciphertext.iv.asList().shuffled().toByteArray(),
                                Ciphertext.Authenticated.Integrated(
                                    ciphertext.ciphertext.algorithm as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>,
                                    ciphertext.ciphertext.encryptedData,
                                    authTag = ciphertext.authenticatedCiphertext.authTag,
                                    aad = ciphertext.authenticatedCiphertext.authenticatedData
                                ) as Ciphertext<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>
                            )

                        val wrongIVDecrypted = wrongIV.decrypt(key)
                        wrongIVDecrypted shouldNot succeed


                        if (aad != null) {
                            SealedBox.WithIV<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>(
                                iv = ciphertext.iv,
                                Ciphertext.Authenticated.Integrated(
                                    ciphertext.ciphertext.algorithm as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>,
                                    ciphertext.ciphertext.encryptedData,
                                    authTag = ciphertext.authenticatedCiphertext.authTag,
                                    aad = null
                                ) as Ciphertext<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>
                            ).decrypt(key) shouldNot succeed

                        }
                        SealedBox.WithIV<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>(
                            iv = ciphertext.iv,
                            Ciphertext.Authenticated.Integrated(
                                ciphertext.ciphertext.algorithm as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>,
                                ciphertext.ciphertext.encryptedData,
                                authTag = ciphertext.authenticatedCiphertext.authTag.asList().shuffled().toByteArray(),
                                aad = ciphertext.authenticatedCiphertext.authenticatedData
                            )
                                    as Ciphertext<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>
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
                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_1,
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_1,
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_1,


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256,
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256,
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256,


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_384,
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384,
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_384,


                SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512,
                SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512,
                SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512,
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
                            nameFn = { "IV: " + it.toHexString()?.substring(0..8) },
                            Random.Default.nextBytes((it.iv.ivLen.bytes).toInt()),
                            Random.Default.nextBytes((it.iv.ivLen.bytes).toInt()),
                        ) { iv ->
                            withData(
                                nameFn = { "AAD: " + it?.toHexString()?.substring(0..8) },
                                Random.Default.nextBytes(32),
                                null
                            ) { aad ->
                                val ciphertext =
                                    key.encrypt(iv, plaintext, aad, macInputFun)
                                        .getOrThrow()

                                key.encrypt(iv, plaintext, aad) { _, _, _ ->
                                    "Manila".encodeToByteArray()
                                }.getOrThrow() shouldNotBe ciphertext

                                //no randomness. must be equal
                                val randomIV = it.randomIV()
                                key.encrypt(randomIV, plaintext, aad) { _, _, _ ->
                                    "Manila".encodeToByteArray()
                                }.getOrThrow() shouldBe key.encrypt(
                                    randomIV,
                                    plaintext,
                                    aad
                                ) { _, _, _ ->
                                    "Manila".encodeToByteArray()
                                }.getOrThrow()


                                ciphertext.iv shouldBe iv
                                ciphertext.iv.shouldNotBeNull()
                                ciphertext.ciphertext.shouldBeInstanceOf<Ciphertext.Authenticated.WithDedicatedMac>()
                                ciphertext.authenticatedCiphertext.authenticatedData shouldBe aad

                                val decrypted = ciphertext.decrypt(key, macInputFun).getOrThrow()
                                decrypted shouldBe plaintext

                                val wrongDecrypted = ciphertext.decrypt(
                                    it.randomKey(),
                                    dedicatedMacInputCalculation = macInputFun
                                )
                                wrongDecrypted shouldNot succeed

                                val wrongCiphertext =
                                    ciphertext.ciphertext.algorithm.sealedBox(
                                        ciphertext.iv,
                                        Random.Default.nextBytes(ciphertext.ciphertext.encryptedData.size),
                                        authTag = ciphertext.authenticatedCiphertext.authTag,
                                        aad = ciphertext.authenticatedCiphertext.authenticatedData
                                    )

                                val wrongWrongDecrypted = wrongCiphertext.decrypt(
                                    it.randomKey(),
                                    dedicatedMacInputCalculation = macInputFun
                                )
                                wrongWrongDecrypted shouldNot succeed

                                val wrongRightDecrypted =
                                    wrongCiphertext.decrypt(key, dedicatedMacInputCalculation = macInputFun)
                                wrongRightDecrypted shouldNot succeed

                                val wrongIV =
                                    ciphertext.ciphertext.algorithm.sealedBox(
                                        iv = ciphertext.iv.asList().shuffled().toByteArray(),
                                        ciphertext.ciphertext.encryptedData,
                                        ciphertext.authenticatedCiphertext.authTag,
                                        ciphertext.authenticatedCiphertext.authenticatedData
                                    )

                                val wrongIVDecrypted =
                                    wrongIV.decrypt(
                                        key,
                                        dedicatedMacInputCalculation = macInputFun
                                    )
                                wrongIVDecrypted shouldNot succeed
                                SealedBox.WithIV<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>(
                                    iv = ciphertext.iv.asList().shuffled().toByteArray(),
                                    Ciphertext.Authenticated.WithDedicatedMac(
                                        ciphertext.ciphertext.algorithm,
                                        ciphertext.ciphertext.encryptedData,
                                        authTag = ciphertext.authenticatedCiphertext.authTag,
                                        aad = ciphertext.authenticatedCiphertext.authenticatedData,
                                    ) as Ciphertext<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>
                                ).decrypt(
                                    key,
                                    dedicatedMacInputCalculation = macInputFun
                                ) shouldNot succeed

                                SealedBox.WithIV<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>(
                                    iv = ciphertext.iv,
                                    Ciphertext.Authenticated.WithDedicatedMac(
                                        ciphertext.ciphertext.algorithm,
                                        ciphertext.ciphertext.encryptedData,
                                        authTag = ciphertext.authenticatedCiphertext.authTag,
                                        aad = ciphertext.authenticatedCiphertext.authenticatedData,
                                    ) as Ciphertext<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>
                                ).decrypt(
                                    SymmetricKey.WithDedicatedMac<IV>(
                                        ciphertext.ciphertext.algorithm,
                                        key.secretKey,
                                        dedicatedMacKey = macKey.asList().shuffled().toByteArray()
                                    ),
                                    dedicatedMacInputCalculation = macInputFun
                                ) shouldNot succeed

                                if (aad != null) {
                                    ciphertext.ciphertext.algorithm.sealedBox(
                                        ciphertext.iv,
                                        ciphertext.ciphertext.encryptedData,
                                        ciphertext.authenticatedCiphertext.authTag,
                                        null
                                    ).decrypt(
                                        key,
                                        dedicatedMacInputCalculation = macInputFun
                                    ) shouldNot succeed

                                }

                                ciphertext.ciphertext.algorithm.sealedBox(
                                    ciphertext.iv,
                                    ciphertext.ciphertext.encryptedData,
                                    ciphertext.authenticatedCiphertext.authTag.asList().shuffled().toByteArray(),
                                    ciphertext.authenticatedCiphertext.authenticatedData
                                ).decrypt(
                                    key,
                                    dedicatedMacInputCalculation = macInputFun
                                ) shouldNot succeed

                                ciphertext.ciphertext.algorithm.sealedBox(
                                    ciphertext.iv,
                                    ciphertext.ciphertext.encryptedData,
                                    ciphertext.authenticatedCiphertext.authTag.asList().shuffled().toByteArray(),
                                    ciphertext.authenticatedCiphertext.authenticatedData
                                ).decrypt(key) { _, _, _ ->
                                    "Szombathely".encodeToByteArray()
                                } shouldNot succeed
                            }

                        }
                    }
                }
            }
        }
    }

    "README" {
        val payload = "More matter, with less Art!".encodeToByteArray()

        //define parameters
        val algorithm = SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512
        val key =
            algorithm.randomKey(dedicatedMacKeyOverride = secureRandom.nextBytesOf(algorithm.keySize.bytes.toInt()))
        val aad = Clock.System.now().toString().encodeToByteArray()

        //we want to customise what is fed into the MAC
        val customMacInputFn =
            fun MAC.(ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray?): ByteArray =
                //this is the default
                (iv ?: byteArrayOf()) + (aad ?: byteArrayOf()) + ciphertext +
                        //but we augment it with the length of AAD:
                        (aad?.size?.encodeToAsn1ContentBytes() ?: byteArrayOf())


        val ciphertext =
            key.encrypt(
                payload,
                aad = aad,
                dedicatedMacAuthTagCalculation = customMacInputFn
            ).getOrThrow(/*TODO Error Handling*/)

        //The ciphertext object is of type Authenticated.WithDedicatedMac, because AES-CBC-HMAC constrains the
        //return type of the previous call to this type.
        //The ciphertext object contains an IV, even though null was passed
        //it also contains AAD and an authTag, in addition to encryptedData
        //because everything is structured, decryption is simple
        val recovered =
            ciphertext.decrypt(key, dedicatedMacInputCalculation = customMacInputFn).getOrThrow(/*TODO Error handling*/)

        recovered shouldBe payload //success!


    }
})