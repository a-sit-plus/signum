package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthType.Authenticated
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual internal fun <T, A : AuthType<K>, I : Nonce, K : KeyType> initCipher(
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A, K> {
    if (!algorithm.requiresNonce()) TODO("UNSUPPORTED")
    else {

        @OptIn(HazardousMaterials::class)
        val nonce = nonce ?: algorithm.randomNonce()

        return when (algorithm) {
            is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaJVM.initCipher(
                key,
                nonce,
                aad
            )

            is SymmetricEncryptionAlgorithm.AES<*, *> -> AESJVM.initCipher(
                algorithm,
                key,
                nonce,
                aad
            )

            else -> TODO("UNSUPPORTED")
        } as CipherParam<T, A, K>
    }
}

actual internal fun <A : AuthType<K>, I : Nonce, K : KeyType> CipherParam<*, A, K>.doEncrypt(data: ByteArray): SealedBox<A, I, K> {
    (this as CipherParam<Cipher, A, K>)
    val jcaCiphertext = platformData.doFinal(data)

    val ciphertext =
        if (alg.authCapability is AuthType.Authenticated<*>) jcaCiphertext.dropLast(((alg.authCapability as AuthType.Authenticated<*>).tagLen.bytes.toInt()).toInt())
            .toByteArray()
        else jcaCiphertext
    val authTag =
        if (alg.authCapability is AuthType.Authenticated<*>) jcaCiphertext.takeLast(((alg.authCapability as AuthType.Authenticated<*>).tagLen.bytes.toInt()).toInt())
            .toByteArray() else null


    return when (alg.requiresNonce()) {
        true -> {
            when (alg.isAuthenticated()) {
                true -> {
                    (alg as SymmetricEncryptionAlgorithm<AuthType.Authenticated<*>, Nonce.Required, *>)
                    alg.sealedBox(nonce!!, ciphertext, authTag!!, aad)
                }
                false -> alg.sealedBox(nonce!!, ciphertext)
            }
        }

        false -> when (alg.isAuthenticated()) {
            true -> {
                (alg as SymmetricEncryptionAlgorithm<AuthType.Authenticated<*>, Nonce.Without, *>)
                alg.sealedBox(ciphertext, authTag!!, aad)
            }

            false -> alg.sealedBox(ciphertext)
        }

    } as SealedBox<A, I, K>
}

val SymmetricEncryptionAlgorithm<*, *,*>.jcaName: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is SymmetricEncryptionAlgorithm.AES.CBC<*, *> -> "AES/CBC/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20-Poly1305"
        else-> TODO("UNSUPPORTED")
    }

val SymmetricEncryptionAlgorithm<*, *,*>.jcaKeySpec: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES<*, *> -> "AES"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20"
        else -> TODO("UNSUPPORTED")
    }

@JvmName("doEncryptAuthenticated")
internal actual fun SealedBox<Authenticated.Integrated, *, KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if(!this.hasNonce()) TODO("UNSUPPORTED")

    if ((algorithm !is SymmetricEncryptionAlgorithm.ChaCha20Poly1305) && (algorithm !is SymmetricEncryptionAlgorithm.AES.GCM)) TODO()

    return gcmLikeDecrypt(
        algorithm as SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.Integrated,
        secretKey,
        nonce,
        encryptedData,
        authTag,
        authenticatedData
    )

}

internal actual fun SealedBox<AuthType.Unauthenticated, *, KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm !is SymmetricEncryptionAlgorithm.AES<*, *>)
        TODO()

    this as SealedBox.WithNonce
    return Cipher.getInstance(algorithm.jcaName).also { cipher ->
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(secretKey, algorithm.jcaKeySpec),
            IvParameterSpec(this@doDecrypt.nonce)
        )
    }.doFinal(encryptedData)
}

internal fun gcmLikeDecrypt(
    algorithm: SymmetricEncryptionAlgorithm<AuthType.Authenticated<KeyType.Integrated>, Nonce.Required, KeyType.Integrated>,
    secretKey: ByteArray,
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    aad: ByteArray?
): ByteArray = Cipher.getInstance(algorithm.jcaName).also { cipher ->
    cipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(secretKey, algorithm.jcaKeySpec),
        if (algorithm is SymmetricEncryptionAlgorithm.AES.GCM)
            GCMParameterSpec(authTag.size * 8, nonce)
        else IvParameterSpec(nonce)
    )
    aad?.let {
        cipher.updateAAD(it)
    }
}.doFinal(encryptedData + authTag)

