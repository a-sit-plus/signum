package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.CipherKind
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object AESJVM {
    fun initCipher(algorithm: SymmetricEncryptionAlgorithm.AES<*>, key: ByteArray, nonce: ByteArray, aad: ByteArray?) =
        Cipher.getInstance(algorithm.jcaName).apply {
            val cipher = algorithm.cipher
            if (cipher is CipherKind.Authenticated.Integrated)
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpec),
                    GCMParameterSpec(cipher.tagLen.bits.toInt(), nonce)
                )
            else if (algorithm is SymmetricEncryptionAlgorithm.AES.CBC<*>) //covers Plain and CBC, because CBC will delegate to here
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key, algorithm.jcaKeySpec),
                    IvParameterSpec(nonce)
                )
            else TODO()
            aad?.let { if (algorithm is SymmetricEncryptionAlgorithm.AES.GCM) updateAAD(it) /*CBC-HMAC we do ourselves*/ }
        }.let { CipherParam<Cipher, CipherKind>(algorithm, it, nonce, aad) }


    fun gcmDecrypt(
        algorithm: SymmetricEncryptionAlgorithm.AES.GCM,
        secretKey: ByteArray,
        nonce: ByteArray,
        encryptedData: ByteArray,
        authTag: ByteArray,
        aad: ByteArray?
    ): ByteArray = Cipher.getInstance(algorithm.jcaName).also { cipher ->
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(secretKey, algorithm.jcaKeySpec),
            GCMParameterSpec(authTag.size * 8, nonce)
        )
        aad?.let {
            cipher.updateAAD(it)
        }
    }.doFinal(encryptedData + authTag)
}
