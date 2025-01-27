package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.KeyType
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@OptIn(HazardousMaterials::class)
internal object AESJVM {
    fun initCipher(
        algorithm: SymmetricEncryptionAlgorithm.AES<*, *, *>,
        key: ByteArray,
        nonce: ByteArray?,
        aad: ByteArray?
    ) =
        Cipher.getInstance(algorithm.jcaName).apply {
            val cipher = algorithm.authCapability
            if (cipher is AuthCapability.Authenticated.Integrated)
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpec),
                    GCMParameterSpec(cipher.tagLength.bits.toInt(), nonce)
                )
            else if (algorithm is SymmetricEncryptionAlgorithm.AES.CBC<*, *>) //covers Plain and CBC, because CBC will delegate to here
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpec),
                    IvParameterSpec(nonce)
                )
            else if ((algorithm is SymmetricEncryptionAlgorithm.AES.ECB) || algorithm is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394) {
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpec),
                )
            }

            else TODO()
            aad?.let { if (algorithm is SymmetricEncryptionAlgorithm.AES.GCM) updateAAD(it) /*CBC-HMAC we do ourselves*/ }
        }.let {
            CipherParam<Cipher, AuthCapability<KeyType>, KeyType>(
                algorithm as SymmetricEncryptionAlgorithm<AuthCapability<KeyType>,*, KeyType>,
                it,
                nonce,
                aad
            )
        }
}
