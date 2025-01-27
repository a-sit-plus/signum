package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import kotlinx.cinterop.ExperimentalForeignApi


actual internal fun <T, A : AuthCapability<out K>, I : NonceTrait, K : KeyType> initCipher(
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A, out K> {

    @OptIn(HazardousMaterials::class)
    val nonce = if (algorithm.requiresNonce())
        nonce ?: algorithm.randomNonce()
    else null
    return CipherParam<ByteArray, AuthCapability<KeyType>, KeyType>(
        algorithm as SymmetricEncryptionAlgorithm<AuthCapability<KeyType>, NonceTrait.Required, KeyType>, key, nonce, aad
    ) as CipherParam<T, A, K>
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> CipherParam<*, A, out K>.doEncrypt(data: ByteArray): SealedBox<A, I, out K> {
    this as CipherParam<ByteArray, A, K>

    return when (alg) {
        is AES<*, *, *> -> AESIOS.encrypt(alg, data, platformData, nonce, aad)
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaIOS.encrypt(data, platformData, nonce!!, aad)
        else -> TODO("ALGORITHM UNSUPPORTED")
    } as SealedBox<A, I, K>
}


@OptIn(ExperimentalForeignApi::class)
internal actual fun SealedBox<Authenticated.Integrated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonceTrait !is NonceTrait.Required) TODO("ALGORITHM UNSUPPORTED")
    this as SealedBox.WithNonce
    return when (algorithm) {
        is AES<*, *, *> -> AESIOS.gcmDecrypt(encryptedData, secretKey, nonce, authTag, authenticatedData)
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaIOS.decrypt(
            encryptedData,
            secretKey,
            nonce,
            authTag,
            authenticatedData
        )

        else -> TODO("ALGORITHM UNSUPPORTED")
    }
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun SealedBox<AuthCapability.Unauthenticated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    require(algorithm is AES<*, *, *>) { "Only AES is supported" }

    return AESIOS.cbcEcbDecrypt(
        algorithm as AES<*, *, *>,
        encryptedData,
        secretKey,
        if (this is SealedBox.WithNonce) nonce else null
    )

}
