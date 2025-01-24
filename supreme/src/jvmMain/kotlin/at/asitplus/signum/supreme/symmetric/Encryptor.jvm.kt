package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual internal fun <T, A : AECapability, E : SymmetricEncryptionAlgorithm<A, *>> initCipher(
    algorithm: E,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A> {
    if (algorithm.nonce is Nonce.Without) TODO()
    algorithm as SymmetricEncryptionAlgorithm<*, Nonce.Required>

    @OptIn(HazardousMaterials::class)
    val nonce = nonce ?: algorithm.randomNonce()

    return when (algorithm) {
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaJVM.initCipher(key, nonce, aad) as CipherParam<T, A>
        is SymmetricEncryptionAlgorithm.AES<*> -> AESJVM.initCipher(algorithm, key, nonce, aad) as CipherParam<T, A>
    }

}

actual internal fun <A : AECapability, I : Nonce> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>> {
    (this as CipherParam<Cipher, A>)
    val jcaCiphertext = platformData.doFinal(data)

    val ciphertext =
        if (alg.cipher is AECapability.Authenticated) jcaCiphertext.dropLast(((alg.cipher as AECapability.Authenticated).tagLen.bytes.toInt()).toInt())
            .toByteArray()
        else jcaCiphertext
    val authTag =
        if (alg.cipher is AECapability.Authenticated) jcaCiphertext.takeLast(((alg.cipher as AECapability.Authenticated).tagLen.bytes.toInt()).toInt())
            .toByteArray() else null

    return (if (alg.nonce is Nonce.Without) when (alg.cipher) {
        is AECapability.Unauthenticated -> (alg as SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Without>).sealedBox(
            ciphertext
        )

        is AECapability.Authenticated -> {
            (alg as SymmetricEncryptionAlgorithm<AECapability.Authenticated, Nonce.Without>).sealedBox(
                ciphertext,
                authTag!!,
                aad
            )
        }

        else -> throw IllegalArgumentException("Unreachable code")
    } else when (alg.cipher) {
        is AECapability.Unauthenticated -> (alg as SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Required>).sealedBox(
            nonce!!,
            ciphertext
        )

        is AECapability.Authenticated -> {
            (alg as SymmetricEncryptionAlgorithm<AECapability.Authenticated, Nonce.Required>).sealedBox(
                nonce!!,
                ciphertext,
                authTag!!,
                aad
            )
        }

        else -> throw IllegalArgumentException("Unreachable code")
    }) as SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
}

val SymmetricEncryptionAlgorithm<*, *>.jcaName: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is SymmetricEncryptionAlgorithm.AES.CBC<*> -> "AES/CBC/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20-Poly1305"
    }

val SymmetricEncryptionAlgorithm<*, *>.jcaKeySpec: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES<*> -> "AES"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20"
    }

@JvmName("doEncryptAuthenticated")
actual internal fun SealedBox<AECapability.Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<AECapability.Authenticated.Integrated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    this as SealedBox.WithNonce

    if ((algorithm !is SymmetricEncryptionAlgorithm.ChaCha20Poly1305) && (algorithm !is SymmetricEncryptionAlgorithm.AES.GCM)) TODO()

    return gcmLikeDecrypt(
        algorithm as SymmetricEncryptionAlgorithm<AECapability.Authenticated, Nonce.Required>,
        secretKey,
        nonce,
        encryptedData,
        authTag,
        authenticatedData
    )

}

actual internal fun SealedBox<AECapability.Unauthenticated, *, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm !is SymmetricEncryptionAlgorithm.AES<*>)
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
    algorithm: SymmetricEncryptionAlgorithm<AECapability.Authenticated, Nonce.Required>,
    secretKey: ByteArray,
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    aad: ByteArray?
): ByteArray = Cipher.getInstance(algorithm.jcaName).also { cipher ->
    cipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(secretKey, algorithm.jcaKeySpec),
        if(algorithm is SymmetricEncryptionAlgorithm.AES.GCM)
        GCMParameterSpec(authTag.size * 8, nonce)
        else IvParameterSpec(nonce)
    )
    aad?.let {
        cipher.updateAAD(it)
    }
}.doFinal(encryptedData + authTag)

