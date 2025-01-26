package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthType.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import kotlinx.cinterop.ExperimentalForeignApi


actual internal fun <T, A : AuthType<out K>, I : Nonce, K : KeyType> initCipher(
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A, out K> {
    if (algorithm.nonce !is Nonce.Required) TODO("ALGORITHM UNSUPPORTED")
    algorithm as SymmetricEncryptionAlgorithm<A, Nonce.Required, K>

    @OptIn(HazardousMaterials::class)
    val nonce = nonce ?: algorithm.randomNonce()
    return CipherParam<ByteArray, AuthType<KeyType>, KeyType>(
        algorithm as SymmetricEncryptionAlgorithm<AuthType<KeyType>, Nonce.Required, KeyType>, key, nonce, aad
    ) as CipherParam<T, A, K>
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun <A : AuthType<out K>, I : Nonce, K : KeyType> CipherParam<*, A, out K>.doEncrypt(data: ByteArray): SealedBox<A, I, out K> {
    this as CipherParam<ByteArray, A, K>
    if (alg.nonce !is Nonce.Required) TODO("ALGORITHM UNSUPPORTED")

    require(nonce != null)


    return when (alg) {
        is AES<*, *> -> AESIOS.encrypt(alg, data, platformData, nonce, aad)
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaIOS.encrypt(data, platformData, nonce, aad)
        else -> TODO("ALGORITHM UNSUPPORTED")
    } as SealedBox<A, I, K>
}


@OptIn(ExperimentalForeignApi::class)
internal actual fun SealedBox<Authenticated.Integrated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonce !is Nonce.Required) TODO("ALGORITHM UNSUPPORTED")
    this as SealedBox.WithNonce
    return when (algorithm) {
        is AES<*, *> -> AESIOS.gcmDecrypt(encryptedData, secretKey, nonce, authTag, authenticatedData)
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
internal actual fun SealedBox<AuthType.Unauthenticated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonce !is Nonce.Required) TODO()
    this as SealedBox.WithNonce
    require(algorithm is AES<*, *>) { "Only AES is supported" }

    return AESIOS.cbcDecrypt(algorithm as AES<*, *>, encryptedData, secretKey, nonce)

}
