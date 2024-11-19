package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import org.kotlincrypto.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private val secureRandom = SecureRandom()

actual internal fun initCipher(
    algorithm: EncryptionAlgorithm,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): PlatformCipher {
    val nonce = iv ?: ByteArray(algorithm.keyNumBits.toInt() / 8).apply { secureRandom.nextBytes(this) }
    return Cipher.getInstance(algorithm.jcaName).apply {
        if( algorithm is EncryptionAlgorithm.AES.GCM)
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, algorithm.jcaKeySpec), GCMParameterSpec(algorithm.tagNumBits.toInt(),nonce))
        aad?.let { updateAAD(it) }
    }.let { AESContainer(algorithm, nonce, aad, it) }
}



private class AESContainer(
    val alg: EncryptionAlgorithm,
    val iv: ByteArray?,
    val aad: ByteArray?,
    val cipher: Cipher
)

actual internal fun PlatformCipher.encrypt(data: ByteArray): KmmResult<Ciphertext> {
    (this as AESContainer)
    val jcaCiphertext =
        catchingUnwrapped { cipher.doFinal(data) }.getOrElse { return KmmResult.failure(it) }

    val ciphertext =
        if (alg is EncryptionAlgorithm.Authenticated) jcaCiphertext.dropLast(((alg as EncryptionAlgorithm.Authenticated).tagNumBits / 8u).toInt())
            .toByteArray()
        else jcaCiphertext
    val authtag =
        if (alg is EncryptionAlgorithm.Authenticated) jcaCiphertext.takeLast(((alg as EncryptionAlgorithm.Authenticated).tagNumBits / 8u).toInt())
            .toByteArray() else null

    return KmmResult.success(
        if (authtag != null) Ciphertext.Authenticated(ciphertext, iv, authtag, aad)
        else Ciphertext(ciphertext, iv)
    )
}

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