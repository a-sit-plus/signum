package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import kotlinx.cinterop.ExperimentalForeignApi


internal actual fun <T, A : AECapability, E : SymmetricEncryptionAlgorithm<A, *>> initCipher(
    algorithm: E,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A> {
    if (algorithm.nonce !is Nonce.Required) TODO()
    algorithm as SymmetricEncryptionAlgorithm<*, Nonce.Required>

    @OptIn(HazardousMaterials::class)
    val nonce = nonce ?: algorithm.randomNonce()
    return CipherParam<ByteArray, A>(algorithm, key, nonce, aad) as CipherParam<T, A>
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun <A : AECapability, I : Nonce> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>> {
    this as CipherParam<ByteArray, A>
    if (alg.nonce !is Nonce.Required) TODO()

    require(nonce != null)

    return when (alg) {
        is AES<*> -> AESIOS.encrypt(alg, data, platformData, nonce, aad)
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaIOS.encrypt(data, platformData, nonce, aad)
    } as SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
}


@OptIn(ExperimentalForeignApi::class)
actual internal fun SealedBox<AECapability.Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<AECapability.Authenticated.Integrated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonce !is Nonce.Required) TODO()
    this as SealedBox.WithNonce
    return when (algorithm) {
        is AES<*> -> AESIOS.gcmDecrypt(encryptedData, secretKey, nonce, authTag, authenticatedData)
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaIOS.decrypt(
            encryptedData,
            secretKey,
            nonce,
            authTag,
            authenticatedData
        )
    }
}

@OptIn(ExperimentalForeignApi::class)
actual internal fun SealedBox<AECapability.Unauthenticated, *, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonce !is Nonce.Required) TODO()
    this as SealedBox.WithNonce
    require(algorithm is AES<*>) { "Only AES is supported" }

    return AESIOS.cbcDecrypt(algorithm as AES<*>, encryptedData, secretKey, nonce)

}
