package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import kotlinx.cinterop.ExperimentalForeignApi


internal actual fun <T, A : CipherKind, E : SymmetricEncryptionAlgorithm<A, *>> initCipher(
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
internal actual fun <A : CipherKind, I : Nonce> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>> {
    this as CipherParam<ByteArray, A>
    if (alg.nonce !is Nonce.Required) TODO()

    require(nonce != null)

    if (alg !is SymmetricEncryptionAlgorithm.AES<*>)
        TODO()


    return when (alg) {

        is AES<*> -> AESIOS.encrypt(alg, data, platformData, nonce, aad)

        else -> TODO()
    } as SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
}


@OptIn(ExperimentalForeignApi::class)
actual internal fun SealedBox<CipherKind.Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonce !is Nonce.Required) TODO()
    this as SealedBox.WithNonce
    require(algorithm is AES<*>) { "Only AES is supported" }

    return AESIOS.gcmDecrypt(encryptedData, secretKey, nonce, authTag, authenticatedData)

}

@OptIn(ExperimentalForeignApi::class)
actual internal fun SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonce !is Nonce.Required) TODO()
    this as SealedBox.WithNonce
    require(algorithm is AES<*>) { "Only AES is supported" }

    return AESIOS.cbcDecrypt(algorithm as AES<*>, encryptedData, secretKey, nonce)

}
