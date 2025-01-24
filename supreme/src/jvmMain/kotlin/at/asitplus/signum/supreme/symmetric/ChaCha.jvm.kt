package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.AECapability
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object ChaChaJVM {
    fun initCipher(key: ByteArray, nonce: ByteArray, aad: ByteArray?): CipherParam<Cipher, AECapability.Authenticated> =
        Cipher.getInstance(SymmetricEncryptionAlgorithm.ChaCha20Poly1305.jcaName).apply {
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, SymmetricEncryptionAlgorithm.ChaCha20Poly1305.jcaKeySpec),
                IvParameterSpec(nonce)
            )
            aad?.let {  updateAAD(it) }
        }.let { CipherParam(SymmetricEncryptionAlgorithm.ChaCha20Poly1305, it, nonce, aad) }
}