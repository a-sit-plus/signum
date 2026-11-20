package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.SealedBox
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.from
import at.asitplus.signum.indispensable.symmetric.sealedBox
import at.asitplus.signum.internals.swiftcall
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import at.asitplus.signum.supreme.symmetric.internal.ios.ChaCha
import kotlinx.cinterop.ExperimentalForeignApi


internal object ChaChaIOS {
    @OptIn(ExperimentalForeignApi::class)
    @Suppress("FINAL_UPPER_BOUND")
    fun <E: SymmetricEncryptionAlgorithm.ChaCha20Poly1305> encrypt(
        algorithm: E,
        data: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray?
    ): SealedBox<E> {
        val ciphertext = ChaCha.encrypt(data.toNSData(), key.toNSData(), nonce.toNSData(), aad?.toNSData())
            ?: throw UnsupportedOperationException("Error from swift code!")
        return algorithm.sealedBox.withNonce(ciphertext.iv().toByteArray()).from(
            ciphertext.ciphertext().toByteArray(),
            ciphertext.authTag().toByteArray()
        ).getOrThrow()

    }

    internal fun decrypt(
        encryptedData: ByteArray,
        secretKey: ByteArray,
        nonce: ByteArray,
        authTag: ByteArray,
        authenticatedData: ByteArray?
    ): ByteArray = swiftcall {
        @OptIn(ExperimentalForeignApi::class)
        ChaCha.decrypt(
            encryptedData.toNSData(),
            secretKey.toNSData(),
            nonce.toNSData(),
            authTag.toNSData(),
            authenticatedData?.toNSData(),
            error
        )
    }.toByteArray()

}

