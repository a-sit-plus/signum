package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object ChaChaJVM {
    fun initCipher(mode: PlatformCipher.Mode, key: ByteArray, nonce: ByteArray, aad: ByteArray?): Cipher =
        Cipher.getInstance(SymmetricEncryptionAlgorithm.ChaCha20Poly1305.jcaName).apply {
            init(
                mode.jcaCipherMode,
                SecretKeySpec(key, SymmetricEncryptionAlgorithm.ChaCha20Poly1305.jcaKeySpec),
                IvParameterSpec(nonce)
            )
            aad?.let { updateAAD(it) }
        }
}