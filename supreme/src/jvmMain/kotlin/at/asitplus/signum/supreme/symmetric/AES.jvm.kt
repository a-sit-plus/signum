package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.AuthType
import at.asitplus.signum.indispensable.symmetric.KeyType
import at.asitplus.signum.indispensable.symmetric.Nonce
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
            if (cipher is AuthType.Authenticated.Integrated)
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpec),
                    GCMParameterSpec(cipher.tagLen.bits.toInt(), nonce)
                )
            else if (algorithm is SymmetricEncryptionAlgorithm.AES.CBC<*, *>) //covers Plain and CBC, because CBC will delegate to here
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpec),
                    IvParameterSpec(nonce)
                )
            else if (algorithm is SymmetricEncryptionAlgorithm.AES.ECB) {
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpec),
                )
            } else TODO()
            aad?.let { if (algorithm is SymmetricEncryptionAlgorithm.AES.GCM) updateAAD(it) /*CBC-HMAC we do ourselves*/ }
        }.let {
            CipherParam<Cipher, AuthType<KeyType>, KeyType>(
                algorithm as SymmetricEncryptionAlgorithm<AuthType<KeyType>,*, KeyType>,
                it,
                nonce,
                aad
            )
        }
}
