import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.CipherKind
import at.asitplus.signum.indispensable.symmetric.IV
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.indispensable.symmetric.authTag
import at.asitplus.signum.indispensable.symmetric.iv
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import at.asitplus.signum.supreme.symmetric.randomIV
import at.asitplus.signum.supreme.symmetric.randomKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import javax.crypto.Cipher
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
                nameFn = { "iv: ${it.size} bytes" }, alg.randomIV(), alg.randomIV()
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
                            Cipher.getInstance(if (alg.cipher is CipherKind.Unauthenticated) "AES/CBC/PKCS5PADDING" else "AES/GCM/NoPadding")

                        if (alg is SymmetricEncryptionAlgorithm.AES.GCM) {
                            //GCM need to cast key, because alg is AES with no mode of ops, since we mix CBC and GCM in the test input
                            val own = (secretKey as SymmetricKey<CipherKind.Authenticated,IV.Required>).encrypt(iv = iv, data = data,aad)
                                .getOrThrow()
                            own.cipherKind.shouldBeInstanceOf<CipherKind.Authenticated>()
                            jcaCipher.init(
                                Cipher.ENCRYPT_MODE,
                                SecretKeySpec(secretKey.secretKey, "AES"),
                                GCMParameterSpec(
                                    alg.cipher.tagLen.bits.toInt(),
                                    own.iv/*use our own auto-generated IV*/
                                )
                            )
                            if (aad != null) jcaCipher.updateAAD(aad)

                            val encrypted = jcaCipher.doFinal(data)

                            (own.encryptedData + own.authTag) shouldBe encrypted

                            jcaCipher.init(
                                Cipher.DECRYPT_MODE,
                                SecretKeySpec(secretKey.secretKey, "AES"),
                                GCMParameterSpec(
                                    alg.cipher.tagLen.bits.toInt(),
                                    own.iv/*use our own auto-generated IV*/
                                )
                            )
                            if (aad != null) jcaCipher.updateAAD(aad)
                            own.decrypt(secretKey).getOrThrow() shouldBe jcaCipher.doFinal(encrypted)


                        } else {
                            //CBC
                            val own = secretKey.encrypt(data).getOrThrow()
                            jcaCipher.init(
                                Cipher.ENCRYPT_MODE,
                                SecretKeySpec(secretKey.secretKey, "AES"),
                                IvParameterSpec(own.iv)/*use our own auto-generated IV, if null iv was provided*/
                            )
                            val encrypted = jcaCipher.doFinal(data)

                            own.encryptedData shouldBe encrypted

                            jcaCipher.init(
                                Cipher.DECRYPT_MODE,
                                SecretKeySpec(secretKey.secretKey, "AES"),
                                IvParameterSpec(own.iv)/*use our own auto-generated IV, if null iv was provided*/
                            )
                            own.decrypt(secretKey).getOrThrow() shouldBe jcaCipher.doFinal(encrypted)

                        }
                    }
                }
            }
        }
    }
})