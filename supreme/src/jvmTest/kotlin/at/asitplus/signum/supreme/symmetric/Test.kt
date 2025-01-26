import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.succeed
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.discouraged.andPredefinedNonce
import at.asitplus.signum.supreme.symmetric.discouraged.encrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import at.asitplus.signum.supreme.symmetric.randomKey
import at.asitplus.signum.supreme.symmetric.randomNonce
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.matchers.shouldNotBe
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

@OptIn(HazardousMaterials::class)
class JvmSymmetricTest : FreeSpec({

    "Against JCA" - {
        "AES" - {
            withData(
                SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN,
                SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN,

                //JVM knows no AES-CBC-HMAC
                SymmetricEncryptionAlgorithm.AES_128.GCM,
                SymmetricEncryptionAlgorithm.AES_192.GCM,
                SymmetricEncryptionAlgorithm.AES_256.GCM,

                ) { alg ->
                withData(
                    nameFn = { "iv: ${it.size} bytes" }, alg.randomNonce(), alg.randomNonce()
                ) { iv ->
                    withData(
                        nameFn = { "aad: ${it?.size} bytes" }, alg.randomNonce(), alg.randomNonce(),

                        Random.nextBytes(19), null
                    ) { aad ->
                        withData(
                            nameFn = { "data: ${it.size} bytes" }, alg.randomNonce(), alg.randomNonce(),
                            Random.nextBytes(19),
                            Random.nextBytes(1),
                            Random.nextBytes(1234),
                            Random.nextBytes(54),
                            Random.nextBytes(16),
                            Random.nextBytes(32),
                            Random.nextBytes(256),
                        ) { data ->


                            val jcaCipher =
                                Cipher.getInstance(if (alg.authCapability is AuthType.Unauthenticated) "AES/CBC/PKCS5PADDING" else "AES/GCM/NoPadding")

                            if (alg is SymmetricEncryptionAlgorithm.AES.GCM) {
                                val secretKey = alg.randomKey()
                                //GCM need to cast key, because alg is AES with no mode of ops, since we mix CBC and GCM in the test input
                                val own =
                                    (secretKey as SymmetricKey<AuthType.Authenticated<KeyType.Integrated>, Nonce.Required, KeyType.Integrated>).andPredefinedNonce(
                                        iv
                                    ).encrypt(
                                        data = data,
                                        aad
                                    )
                                        .getOrThrow()
                                own.isAuthenticated() shouldBe true
                                jcaCipher.init(
                                    Cipher.ENCRYPT_MODE,
                                    SecretKeySpec(secretKey.secretKey, "AES"),
                                    GCMParameterSpec(
                                        alg.authCapability.tagLen.bits.toInt(),
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
                                        alg.authCapability.tagLen.bits.toInt(),
                                        own.nonce/*use our own auto-generated IV*/
                                    )
                                )
                                if (aad != null) jcaCipher.updateAAD(aad)

                                own.decrypt(secretKey).getOrThrow() shouldBe jcaCipher.doFinal(encrypted)

                                val wrongKey = own.algorithm.randomKey()
                                own.decrypt(wrongKey) shouldNot succeed

                                own.algorithm.sealedBox(
                                    own.algorithm.randomNonce(),
                                    own.encryptedData,
                                    own.authTag,
                                    own.authenticatedData
                                ).decrypt(secretKey) shouldNot succeed


                            } else {
                                alg as SymmetricEncryptionAlgorithm.AES.CBC.Unauthenticated
                                val secretKey = alg.randomKey()
                                //CBC
                                val own = secretKey.encrypt(data).getOrThrow()
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
                                own.decrypt(secretKey).getOrThrow() shouldBe jcaCipher.doFinal(encrypted)

                                //this could succeed if we're lucky and padding works out
                                own.decrypt(own.algorithm.randomKey()).onSuccess {
                                    it shouldNotBe data
                                }

                                if (data.size < alg.blockSize.bytes.toInt())
                                    alg.sealedBox(
                                        own.algorithm.randomNonce(),
                                        own.encryptedData
                                    ).decrypt(secretKey) shouldNot succeed

                            }
                        }
                    }
                }
            }
            "ECB" - {
                withData(

                    SymmetricEncryptionAlgorithm.AES_128.ECB,
                    SymmetricEncryptionAlgorithm.AES_192.ECB,
                    SymmetricEncryptionAlgorithm.AES_256.ECB,

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
                    ) { data ->


                        val jcaCipher =
                            Cipher.getInstance("AES/ECB/PKCS5PADDING")

                        val secretKey = alg.randomKey()
                        //CBC
                        val own = secretKey.encrypt(data).getOrThrow()
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
                        own.decrypt(secretKey).getOrThrow() shouldBe jcaCipher.doFinal(encrypted)

                        //we might get lucky here
                        own.decrypt(own.algorithm.randomKey()).onSuccess {
                            it shouldNotBe data
                        }

                        alg.sealedBox(own.encryptedData).decrypt(secretKey) should succeed
                    }
                }
            }
        }
    }

    "ChaCha20-Poly1305" - {
        val alg = SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        withData(
            nameFn = { "iv: ${it?.size} bytes" }, alg.randomNonce(), alg.randomNonce(), null
        ) { nonce ->
            withData(Random.nextBytes(19), null) { aad ->
                withData(
                    Random.nextBytes(19),
                    Random.nextBytes(1),
                    Random.nextBytes(0),
                    Random.nextBytes(1234),
                    Random.nextBytes(54),
                    Random.nextBytes(16),
                    Random.nextBytes(32),
                    Random.nextBytes(256),
                ) { data ->
                    val secretKey = alg.randomKey()
                    val jcaCipher = Cipher.getInstance("ChaCha20-Poly1305");

                    val box = if (nonce != null) secretKey.andPredefinedNonce(nonce).encrypt(data, aad).getOrThrow()
                    else secretKey.encrypt(data, aad).getOrThrow()


                    jcaCipher.init(
                        Cipher.ENCRYPT_MODE,
                        SecretKeySpec(secretKey.secretKey, "ChaCha"),
                        IvParameterSpec(box.nonce) /*need to do this, otherwise we get a random nonce*/
                    )

                    if (aad != null) jcaCipher.updateAAD(aad)

                    val fromJCA = jcaCipher.doFinal(data)

                    box.nonce.shouldNotBeNull()
                    box.nonce.size shouldBe alg.nonce.length.bytes.toInt()
                    box.isAuthenticated() shouldBe true
                    (box.encryptedData + box.authTag) shouldBe fromJCA
                    box.decrypt(secretKey).getOrThrow() shouldBe data

                }
            }
        }
    }
})