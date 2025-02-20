package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.ImplementationError
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import kotlinx.cinterop.ExperimentalForeignApi


internal actual fun <T, A : AuthCapability<out K>, I : NonceTrait, K : KeyType> initCipher(
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): PlatformCipher<T, A, out K> {

    @OptIn(HazardousMaterials::class)
    val nonce = if (algorithm.requiresNonce()) nonce ?: algorithm.randomNonce() else null

    @Suppress("UNCHECKED_CAST")
    return PlatformCipher<ByteArray, AuthCapability<out KeyType>, KeyType>(
        algorithm, key, nonce, aad
    ) as PlatformCipher<T, A, K>
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> PlatformCipher<*, A, out K>.doEncrypt(data: ByteArray): SealedBox<A, I, out K> {
    @Suppress("UNCHECKED_CAST") (this as PlatformCipher<ByteArray, A, K>)

    @Suppress("UNCHECKED_CAST")
    return when (alg) {
        is AES<*, *, *> -> AESIOS.encrypt(alg, data, platformData, nonce, aad)
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaIOS.encrypt(data, platformData, nonce!!, aad)
        else -> TODO("ALGORITHM $alg UNSUPPORTED")
    } as SealedBox<A, I, K>
}


@OptIn(ExperimentalForeignApi::class)
internal actual fun SealedBox<Authenticated.Integrated, *, out KeyType.Integrated>.doDecryptAEAD(
    secretKey: ByteArray,
    authenticatedData: ByteArray
): ByteArray {
    if (algorithm.nonceTrait !is NonceTrait.Required) TODO("ALGORITHM $algorithm UNSUPPORTED")
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

@OptIn(ExperimentalForeignApi::class, HazardousMaterials::class)
internal actual fun SealedBox<AuthCapability.Unauthenticated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    require(algorithm is AES<*, *, *>) { "Only AES is supported" }

    return AESIOS.cbcEcbCrypt(
        algorithm as AES<*, KeyType.Integrated, *>,
        encrypt = false,
        secretKey,
        if (this is SealedBox.WithNonce) nonce else null,
        encryptedData,
        pad = when (algorithm) {
            is AES.CBC.Unauthenticated, is AES.ECB -> true
            is AES.WRAP.RFC3394 -> false
            else -> throw ImplementationError("Illegal AES encryption state.")

        }
    )

}
