@file:OptIn(SecretExposure::class)

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.InsecureRandom
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.discouraged.andPredefinedNonce
import at.asitplus.signum.supreme.symmetric.discouraged.encrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.engine.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

@OptIn(HazardousMaterials::class, ExperimentalStdlibApi::class)
val JvmSymmetricTest by matrixSuite {

    "Against JCA" - {
        "AES" - {
            listOf(
                    SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
                    SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
                    SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN, //JVM knows no AES-CBC-HMAC
                    SymmetricEncryptionAlgorithm.AES_128.GCM,
                    SymmetricEncryptionAlgorithm.AES_192.GCM,
                    SymmetricEncryptionAlgorithm.AES_256.GCM
                ).asData() - { alg ->
                listOf(alg.randomNonce(), alg.randomNonce()).asData(nameFn = { "iv: ${it.size} bytes" }) - { iv ->
                    listOf(alg.randomNonce(), alg.randomNonce(), Random.nextBytes(19), null).asData(nameFn = { "aad: ${it?.size} bytes" }) - { aad ->
                        listOf(
                                alg.randomNonce(),
                                alg.randomNonce(),
                                Random.nextBytes(19),
                                Random.nextBytes(1),
                                Random.nextBytes(1234),
                                Random.nextBytes(54),
                                Random.nextBytes(16),
                                Random.nextBytes(32),
                                Random.nextBytes(256)
                            ).asData(nameFn = { "data: ${it.size} bytes" }) test { data ->


                            val jcaCipher =
                                Cipher.getInstance(if (!alg.isAuthenticated()) "AES/CBC/PKCS5PADDING" else "AES/GCM/NoPadding")

                            if (alg.isAuthenticated()) {
                                val secretKey = alg.randomKey(random = InsecureRandom)
                                //GCM need to cast key, because alg is AES with no mode of ops, since we mix CBC and GCM in the test input
                                val own =
                                    secretKey.andPredefinedNonce(
                                        iv
                                    ).encrypt(data = data, aad)
                                own.isAuthenticated() shouldBe true
                                jcaCipher.init(
                                    Cipher.ENCRYPT_MODE,
                                    SecretKeySpec(secretKey.secretKey, "AES"),
                                    GCMParameterSpec(
                                        alg.authTagSize.bits.toInt(),
                                        own.nonce/*use our own auto-generated IV*/
                                    )
                                )
                                if (aad != null) jcaCipher.updateAAD(aad)

                                val encrypted = jcaCipher.doFinal(data)

                                (own.encryptedData + own.authTag) shouldBe encrypted

                                jcaCipher.init(
                                    Cipher.DECRYPT_MODE,
                                    SecretKeySpec(secretKey.secretKey, "AES"),
                                    GCMParameterSpec(
                                        alg.authTagSize.bits.toInt(),
                                        own.nonce/*use our own auto-generated IV*/
                                    )
                                )
                                if (aad != null) jcaCipher.updateAAD(aad)



                                own.decrypt(secretKey, aad ?: byteArrayOf()) shouldBe jcaCipher.doFinal(
                                    encrypted
                                )

                                val wrongKey = own.algorithm.randomKey(random = InsecureRandom)
                                shouldThrowAny { own.decrypt(wrongKey) }

                                val box = own.algorithm.sealedBox.withNonce(own.algorithm.randomNonce()).from(
                                    own.encryptedData,
                                    own.authTag,
                                )
                                shouldThrowAny { box.decrypt(secretKey, aad ?: byteArrayOf()) }


                            } else {
                                val secretKey = alg.randomKey(random = InsecureRandom)
                                //CBC
                                val own = secretKey.encrypt(data)
                                jcaCipher.init(
                                    Cipher.ENCRYPT_MODE,
                                    SecretKeySpec(secretKey.secretKey, "AES"),
                                    IvParameterSpec(own.nonce)/*use our own auto-generated IV, if null iv was provided*/
                                )
                                val encrypted = jcaCipher.doFinal(data)

                                own.encryptedData shouldBe encrypted

                                jcaCipher.init(
                                    Cipher.DECRYPT_MODE,
                                    SecretKeySpec(secretKey.secretKey, "AES"),
                                    IvParameterSpec(own.nonce)/*use our own auto-generated IV, if null iv was provided*/
                                )
                                own.decrypt(secretKey) shouldBe jcaCipher.doFinal(encrypted)

                                //this could succeed if we're lucky and padding works out
                                runCatching { own.decrypt(own.algorithm.randomKey(random = InsecureRandom)) }.onSuccess {
                                    it shouldNotBe data
                                }

                                if (data.size < alg.blockSize.bytes.toInt()) {
                                    val box = alg.sealedBox.withNonce(own.algorithm.randomNonce()).from(own.encryptedData)
                                    runCatching { box.decrypt(secretKey) }.onSuccess { it shouldNotBe data }
                                }

                            }
                        }
                    }
                }
            }
            "ECB + WRAP" - {
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
                    ).asData() - { alg ->

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
                        ).asData(nameFn = { "data: ${it.size} bytes" }) - { data ->

                        val secretKey = runBlocking { alg.randomKey(random = InsecureRandom) }

                        //EBC
                        if (alg is SymmetricEncryptionAlgorithm.AES.ECB) {
                            "ECB" {
                                val jcaCipher =
                                    Cipher.getInstance("AES/ECB/PKCS5PADDING")

                                val own = secretKey.encrypt(data)
                                jcaCipher.init(
                                    Cipher.ENCRYPT_MODE,
                                    SecretKeySpec(secretKey.secretKey, "AES"),
                                )
                                val encrypted = jcaCipher.doFinal(data)

                                own.encryptedData shouldBe encrypted

                                jcaCipher.init(
                                    Cipher.DECRYPT_MODE,
                                    SecretKeySpec(secretKey.secretKey, "AES"),
                                )
                                own.decrypt(secretKey) shouldBe jcaCipher.doFinal(encrypted)

                                //we might get lucky here
                                runCatching { own.decrypt(own.algorithm.randomKey(random = InsecureRandom)) }.onSuccess {
                                    it shouldNotBe data
                                }

                                alg.sealedBox.from(own.encryptedData).decrypt(secretKey) shouldBe data
                            }
                        } else if (alg is SymmetricEncryptionAlgorithm.AES.ECB_NOPADDING) {
                            "ECB NoPadding" - {
                                if (data.size % alg.blockSize.bytes.toInt() == 0) {
                                    "OK" {
                                        val jcaCipher =
                                            Cipher.getInstance("AES/ECB/NoPadding")

                                        val own = secretKey.encrypt(data)
                                        jcaCipher.init(
                                            Cipher.ENCRYPT_MODE,
                                            SecretKeySpec(secretKey.secretKey, "AES"),
                                        )
                                        val encrypted = jcaCipher.doFinal(data)

                                        own.encryptedData shouldBe encrypted

                                        jcaCipher.init(
                                            Cipher.DECRYPT_MODE,
                                            SecretKeySpec(secretKey.secretKey, "AES"),
                                        )
                                        own.decrypt(secretKey) shouldBe jcaCipher.doFinal(encrypted)

                                        //we might get lucky here
                                        runCatching { own.decrypt(own.algorithm.randomKey(random = InsecureRandom)) }.onSuccess {
                                            it shouldNotBe data
                                        }

                                        alg.sealedBox.from(own.encryptedData)
                                            .decrypt(secretKey) shouldBe data
                                    }
                                } else "Illegal input size" {
                                    shouldThrow<Throwable> { secretKey.encrypt(data) }
                                }
                            }
                        } else {
                            "WRAP" {
                                val shouldSucceed = (data.size >= 16) && (data.size % 8 == 0)
                                val jcaCipher =
                                    Cipher.getInstance("AESWrap")
                                val trial = runCatching { secretKey.encrypt(data) }
                                trial.isSuccess shouldBe shouldSucceed

                                jcaCipher.init(
                                    Cipher.ENCRYPT_MODE,
                                    SecretKeySpec(secretKey.secretKey, "AES"),
                                )
                                val jcaTrial = runCatching {
                                    jcaCipher.doFinal(data)
                                }
                                jcaTrial.isSuccess shouldBe shouldSucceed

                                if (shouldSucceed) {
                                    val own = trial.getOrThrow()
                                    val encrypted = jcaTrial.getOrThrow()
                                    own.encryptedData shouldBe encrypted

                                    jcaCipher.init(
                                        Cipher.DECRYPT_MODE,
                                        SecretKeySpec(secretKey.secretKey, "AES"),
                                    )
                                    own.decrypt(secretKey) shouldBe jcaCipher.doFinal(encrypted)

                                    //we might get lucky here
                                    runCatching { own.decrypt(own.algorithm.randomKey(random = InsecureRandom)) }.onSuccess {
                                        it shouldNotBe data
                                    }

                                    alg.sealedBox.from(own.encryptedData).decrypt(secretKey) shouldBe data
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    "ChaCha20-Poly1305" - {
        val alg = SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        listOf(alg.randomNonce(), alg.randomNonce(), null).asData(nameFn = { "iv: ${it?.size} bytes" }) - { nonce ->
            listOf(Random.nextBytes(19), null).asData() - { aad ->
                listOf(
                        Random.nextBytes(19),
                        Random.nextBytes(1),
                        Random.nextBytes(0),
                        Random.nextBytes(1234),
                        Random.nextBytes(54),
                        Random.nextBytes(16),
                        Random.nextBytes(32),
                        Random.nextBytes(256)
                    ).asData(nameFn = { "Random ${it.size} bytes" }) test { data ->
                    val secretKey = alg.randomKey(random = InsecureRandom)
                    val jcaCipher = Cipher.getInstance("ChaCha20-Poly1305");

                    val box = if (nonce != null) secretKey.andPredefinedNonce(nonce).encrypt(data, aad)
                    else secretKey.encrypt(data, aad)


                    jcaCipher.init(
                        Cipher.ENCRYPT_MODE,
                        SecretKeySpec(secretKey.secretKey, "ChaCha"),
                        IvParameterSpec(box.nonce) /*need to do this, otherwise we get a random nonce*/
                    )

                    if (aad != null) jcaCipher.updateAAD(aad)

                    val fromJCA = jcaCipher.doFinal(data)

                    box.nonce.shouldNotBeNull()
                    box.nonce.size shouldBe alg.nonceSize.bytes.toInt()
                    box.isAuthenticated() shouldBe true
                    (box.encryptedData + box.authTag) shouldBe fromJCA
                    box.decrypt(secretKey, aad ?: byteArrayOf()) shouldBe data

                }
            }
        }
    }
}