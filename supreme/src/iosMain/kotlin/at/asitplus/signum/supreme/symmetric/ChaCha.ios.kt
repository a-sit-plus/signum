package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.KeyType
import at.asitplus.signum.indispensable.symmetric.NonceTrait
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
    fun encrypt(
        data: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray?
    ): SealedBox<AuthCapability.Authenticated.Integrated, NonceTrait.Required, KeyType.Integrated> {
        val ciphertext = ChaCha.encrypt(data.toNSData(), key.toNSData(), nonce.toNSData(), aad?.toNSData())
        if (ciphertext == null) throw UnsupportedOperationException("Error from swift code!")
        @Suppress("UNCHECKED_CAST")
        return SymmetricEncryptionAlgorithm.ChaCha20Poly1305.sealedBox.withNonce( ciphertext.iv().toByteArray()).from(
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

