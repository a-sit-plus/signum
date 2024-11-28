package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.AuthTrait
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.sign.Signer
import org.kotlincrypto.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual internal fun <T, A : AuthTrait, E : EncryptionAlgorithm<A>> initCipher(
    algorithm: E,
    key: ByteArray,
    macKey: ByteArray?,
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T,A> {
    if(algorithm !is EncryptionAlgorithm.WithIV<*>) TODO()
    val nonce = iv ?: algorithm.randomIV()
    return Cipher.getInstance(algorithm.jcaName).apply {
        if (algorithm is EncryptionAlgorithm.AES.GCM)
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, algorithm.jcaKeySpec),
                GCMParameterSpec(algorithm.tagNumBits.toInt(), nonce)
            )
        else if(algorithm is EncryptionAlgorithm.AES.CBC<*>) //covers Plain and CBC, because CBC will delegate to here
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, algorithm.jcaKeySpec),
                IvParameterSpec(nonce)
            )
        else TODO()
        aad?.let { if(algorithm is EncryptionAlgorithm.AES.GCM) updateAAD(it) /*CBC-HMAC we do ourselves*/ }
    }.let { CipherParam<Cipher,A>(algorithm, it, macKey?:key, nonce, aad) as CipherParam<T, A> }
}

actual internal fun <A : AuthTrait> CipherParam<*,A>.encrypt(data: ByteArray): KmmResult<Ciphertext<A, EncryptionAlgorithm<A>>> {
    (this as CipherParam<Cipher,A>)
    val jcaCiphertext =
        catchingUnwrapped { platformData.doFinal(data) }.getOrElse { return KmmResult.failure(it) }

    val ciphertext =
        if (alg is AuthTrait.Authenticated) jcaCiphertext.dropLast((alg.tagNumBits / 8u).toInt())
            .toByteArray()
        else jcaCiphertext
    val authtag =
        if (alg is AuthTrait.Authenticated) jcaCiphertext.takeLast((alg.tagNumBits / 8u).toInt())
            .toByteArray() else null

    return KmmResult.success(
        if (authtag != null) Ciphertext.Authenticated(alg as EncryptionAlgorithm.Authenticated, ciphertext, iv, authtag, aad)
        else Ciphertext.Unauthenticated(alg as EncryptionAlgorithm.Unauthenticated, ciphertext, iv)
    ) as KmmResult<Ciphertext<A, EncryptionAlgorithm<A>>>
}

val EncryptionAlgorithm<*>.jcaName: String
    get() = when (this) {
        is EncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is EncryptionAlgorithm.AES.CBC -> "AES/CBC/PKCS5Padding"
        //  is EncryptionAlgorithm.AES.ECB -> "AES/ECB/NoPadding"
        else -> TODO()
    }

val EncryptionAlgorithm<*>.jcaKeySpec: String
    get() = when (this) {
        is EncryptionAlgorithm.AES -> "AES"
        else -> TODO()
    }

actual internal fun Ciphertext.Authenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray> {
    return catching {
        val wholeInput = encryptedData + authTag
        Cipher.getInstance(algorithm.jcaName).also { cipher ->
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(secretKey, algorithm.jcaKeySpec),
                GCMParameterSpec(authTag.size*8, iv)
            )
            aad?.let {
                cipher.updateAAD(it)
            }
        }.doFinal(wholeInput)
    }
}


actual internal fun Ciphertext.Unauthenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray> = catching {
    return catching {
        Cipher.getInstance(algorithm.jcaName).also { cipher ->
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(secretKey, algorithm.jcaKeySpec),
                IvParameterSpec(iv)
            )
        }.doFinal(encryptedData)
    }
}

