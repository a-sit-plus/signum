package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import at.asitplus.signum.internals.ImplementationError
import kotlinx.cinterop.ExperimentalForeignApi


internal actual suspend fun <A : AuthCapability, I : NonceTrait> initCipher(
    mode: PlatformCipher.Mode,
    algorithm: SymmetricEncryptionAlgorithm<A, I>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): PlatformCipher<A, I> {

    @Suppress("UNCHECKED_CAST")
    return IosPlatformCipher(mode, algorithm, key, nonce, aad)
}


private class IosPlatformCipher<A : AuthCapability, I : NonceTrait>(
    override val mode: PlatformCipher.Mode,
    override val algorithm: SymmetricEncryptionAlgorithm<A, I>,
    override val key: ByteArray,
    override val nonce: ByteArray?,
    override val aad: ByteArray?,
) : PlatformCipher<A, I> {

    //the oneshot ccrypt is fully stateless. no init, no update, no final, so we are stateless here too

    @OptIn(HazardousMaterials::class)
    override suspend fun doDecrypt(data: ByteArray, authTag: ByteArray?): ByteArray {
        require(mode == PlatformCipher.Mode.DECRYPT) { "Cipher not in DECRYPT mode!" }
        return when (algorithm.isAuthenticated()) {
            true -> {
                if (!algorithm.isIntegrated()) throw ImplementationError("iOS AEAD algorithm mapping")
                if (algorithm.nonceTrait !is NonceTrait.Required) TODO("ALGORITHM $algorithm UNSUPPORTED")
                when (algorithm) {
                    is AES<*, *> -> AESIOS.gcmDecrypt(data, key, nonce!!, authTag!!, aad)
                    is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaIOS.decrypt(
                        data,
                        key,
                        nonce!!,
                        authTag!!,
                        aad
                    )
                    else -> TODO("ALGORITHM UNSUPPORTED")
                }
            }

            false -> {
                require(algorithm is AES) { "Only AES is supported" }
                AESIOS.cbcEcbCrypt(
                    algorithm,
                    encrypt = false,
                    key,
                    nonce,
                    data,
                    pad = when (algorithm) {
                        is AES.CBC.Unauthenticated, is AES.ECB -> true
                        is AES.WRAP.RFC3394 -> false
                    }
                )
            }
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    override suspend fun doEncrypt(data: ByteArray): SealedBox<A, I> {
        require(mode == PlatformCipher.Mode.ENCRYPT) { "Cipher not in ENCRYPT mode!" }
        @Suppress("UNCHECKED_CAST")
        return when (algorithm) {
            is AES<*, *> -> AESIOS.encrypt(algorithm, data, key, nonce, aad)
            is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaIOS.encrypt(data, key, nonce!!, aad)
            else -> TODO("ALGORITHM $algorithm UNSUPPORTED")
        } as SealedBox<A, I>
    }
}
