package at.asitplus.signum.supreme.crypt

import at.asitplus.signum.indispensable.AuthTrait
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.SymmetricEncryptionAlgorithm
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual internal fun <T, A : AuthTrait, E : SymmetricEncryptionAlgorithm<A>> initCipher(
    algorithm: E,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A> {
    if (algorithm !is SymmetricEncryptionAlgorithm.WithIV<*>) TODO()
    val nonce = iv ?: algorithm.randomIV()
    return Cipher.getInstance(algorithm.jcaName).apply {
        if (algorithm is SymmetricEncryptionAlgorithm.AES.GCM)
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, algorithm.jcaKeySpec),
                GCMParameterSpec(algorithm.tagNumBits.toInt(), nonce)
            )
        else if (algorithm is SymmetricEncryptionAlgorithm.AES.CBC<*>) //covers Plain and CBC, because CBC will delegate to here
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, algorithm.jcaKeySpec),
                IvParameterSpec(nonce)
            )
        else TODO()
        aad?.let { if (algorithm is SymmetricEncryptionAlgorithm.AES.GCM) updateAAD(it) /*CBC-HMAC we do ourselves*/ }
    }.let { CipherParam<Cipher, A>(algorithm, it, nonce, aad) as CipherParam<T, A> }
}

actual internal fun <A : AuthTrait> CipherParam<*, A>.doEncrypt(data: ByteArray): Ciphertext<A, SymmetricEncryptionAlgorithm<A>> {
    (this as CipherParam<Cipher, A>)
    val jcaCiphertext = platformData.doFinal(data)

    val ciphertext =
        if (alg is AuthTrait.Authenticated) jcaCiphertext.dropLast((alg.tagNumBits / 8u).toInt())
            .toByteArray()
        else jcaCiphertext
    val authtag =
        if (alg is AuthTrait.Authenticated) jcaCiphertext.takeLast((alg.tagNumBits / 8u).toInt())
            .toByteArray() else null

    val result = if (authtag != null) Ciphertext.Authenticated(
        alg as SymmetricEncryptionAlgorithm.Authenticated,
        ciphertext,
        iv,
        authtag,
        aad
    )
    else Ciphertext.Unauthenticated(alg as SymmetricEncryptionAlgorithm.Unauthenticated, ciphertext, iv)

    return result as Ciphertext<A, SymmetricEncryptionAlgorithm<A>>
}

val SymmetricEncryptionAlgorithm<*>.jcaName: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is SymmetricEncryptionAlgorithm.AES.CBC -> "AES/CBC/PKCS5Padding"
        else -> TODO()
    }

val SymmetricEncryptionAlgorithm<*>.jcaKeySpec: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES -> "AES"
        else -> TODO()
    }

actual internal fun Ciphertext.Authenticated.doDecrypt(secretKey: ByteArray): ByteArray {
    val wholeInput = encryptedData + authTag
    return Cipher.getInstance(algorithm.jcaName).also { cipher ->
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(secretKey, algorithm.jcaKeySpec),
            GCMParameterSpec(authTag.size * 8, iv)
        )
        authenticatedData?.let {
            cipher.updateAAD(it)
        }
    }.doFinal(wholeInput)
}


actual internal fun Ciphertext.Unauthenticated.doDecrypt(secretKey: ByteArray): ByteArray {
    return Cipher.getInstance(algorithm.jcaName).also { cipher ->
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(secretKey, algorithm.jcaKeySpec),
            IvParameterSpec(iv)
        )
    }.doFinal(encryptedData)
}

