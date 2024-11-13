package at.asitplus.signum.supreme.crypt

import at.asitplus.signum.indispensable.EncryptionAlgorithm
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual internal fun initCipher(
    cipher: EncryptionAlgorithm,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): PlatformCipher = Cipher.getInstance(cipher.jcaName).apply {
    if (iv == null) init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, cipher.jcaKeySpec))
    else init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, cipher.jcaKeySpec), IvParameterSpec(iv))
    aad?.let {
        updateAAD(it)
    }

}

actual internal fun PlatformCipher.encrypt(data: ByteArray): ByteArray = (this as Cipher).doFinal(data)


val EncryptionAlgorithm.jcaName: String
    get() = when (this) {
        is EncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is EncryptionAlgorithm.AES.CBC -> "AES/CBC/PKCS5Padding"
        is EncryptionAlgorithm.AES.ECB -> "AES/ECB/NoPadding"
    }

val EncryptionAlgorithm.jcaKeySpec: String
    get() = when (this) {
        is EncryptionAlgorithm.AES -> "AES"
    }