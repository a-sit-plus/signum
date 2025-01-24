package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.AECapability
import at.asitplus.signum.indispensable.symmetric.Nonce
import at.asitplus.signum.indispensable.symmetric.SealedBox
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.sealedBox
import at.asitplus.signum.internals.swiftcall
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import at.asitplus.signum.supreme.aes.ChaCha
import kotlinx.cinterop.ExperimentalForeignApi


internal object ChaChaIOS {
    @OptIn(ExperimentalForeignApi::class)
    fun encrypt(
        data: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray?
    ): SealedBox.WithNonce<AECapability.Authenticated, SymmetricEncryptionAlgorithm<AECapability.Authenticated, Nonce.Required>> {
        val ciphertext = ChaCha.encrypt(data.toNSData(), key.toNSData(), nonce.toNSData(), aad?.toNSData())
        if (ciphertext == null) throw UnsupportedOperationException("Error from swift code!")
      return  SymmetricEncryptionAlgorithm.ChaCha20Poly1305.sealedBox(
            ciphertext.iv().toByteArray(),
            ciphertext.ciphertext().toByteArray(),
            ciphertext.authTag().toByteArray(),
            aad
        )

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

