import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.CipherKind
import at.asitplus.signum.indispensable.CipherKind.Unauthenticated
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.SymmetricEncryptionAlgorithm
import at.asitplus.signum.supreme.crypt.decrypt
import at.asitplus.signum.supreme.crypt.encrypt
import at.asitplus.signum.supreme.crypt.randomIV
import at.asitplus.signum.supreme.crypt.randomKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

@OptIn(HazardousMaterials::class)
class JvmAESTest : FreeSpec({

    "Against JCA" - {
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
                nameFn = { "iv: ${it?.size} bytes" }, alg.randomIV(), alg.randomIV()
            ) { iv ->
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

                        val jcaCipher =
                            CipherKind.getInstance(if (alg is SymmetricEncryptionAlgorithm.Unauthenticated) "AES/CBC/PKCS5PADDING" else "AES/GCM/NoPadding")

                        if (alg is SymmetricEncryptionAlgorithm.AES.GCM) {
                            //GCM
                            val own =
                                ((alg as SymmetricEncryptionAlgorithm. WithIV<*>).randomKey()) .encrypt(iv=iv,data=data)
                                    .getOrThrow()
                                    .shouldBeInstanceOf<Ciphertext.Authenticated>()
                            jcaCipher.init(
                                CipherKind.ENCRYPT_MODE,
                                SecretKeySpec(secretKey.secretKey, "AES"),
                                GCMParameterSpec(alg.tagNumBits.toInt(), own.iv/*use our own auto-generated IV*/)
                            )
                            if (aad != null) jcaCipher.updateAAD(aad)

                            val encrypted = jcaCipher.doFinal(data)

                            (own.encryptedData + own.authTag) shouldBe encrypted

                            jcaCipher.init(
                                CipherKind.DECRYPT_MODE,
                                SecretKeySpec(secretKey.secretKey, "AES"),
                                GCMParameterSpec(alg.tagNumBits.toInt(), own.iv/*use our own auto-generated IV*/)
                            )
                            if (aad != null) jcaCipher.updateAAD(aad)
                            own.decrypt(secretKey.secretKey).getOrThrow() shouldBe jcaCipher.doFinal(encrypted)


                        } else {
                            //CBC
                            val own = alg.randomKey().encrypt(data).getOrThrow()
                            jcaCipher.init(
                                CipherKind.ENCRYPT_MODE,
                                SecretKeySpec(secretKey.secretKey, "AES"),
                                IvParameterSpec(own.iv)/*use our own auto-generated IV, if null iv was provided*/
                            )
                            val encrypted = jcaCipher.doFinal(data)

                            own.encryptedData shouldBe encrypted

                            jcaCipher.init(
                                CipherKind.DECRYPT_MODE,
                                SecretKeySpec(secretKey.secretKey, "AES"),
                                IvParameterSpec(own.iv)/*use our own auto-generated IV, if null iv was provided*/
                            )
                            own.decrypt(secretKey.secretKey).getOrThrow() shouldBe jcaCipher.doFinal(encrypted)

                        }
                    }
                }
            }
        }
    }
})