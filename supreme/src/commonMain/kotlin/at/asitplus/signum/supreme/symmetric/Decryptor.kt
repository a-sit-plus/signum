package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.mac.mac

internal class Decryptor<out I: NonceTrait<*>, out E: SymmetricEncryptionAlgorithm<*, I>>(
    val platformCipher: PlatformCipher<SymmetricEncryptionAlgorithm<*, I>>,
    val algorithm: E,
    val authTag: ByteArray?,
    val macKey: ByteArray?
) {
    companion object {
        suspend operator fun <I: NonceTrait<*>, E: SymmetricEncryptionAlgorithm<*, I>> invoke(
            algorithm: E,
            key: ByteArray,
            macKey: ByteArray?,
            nonce: ByteArray?,
            authTag: ByteArray?,
            aad: ByteArray?
        ): Decryptor<I, E> {
            //while it could be argued that we should not check here. we are only calling this chained with decrypt(), so it is fine to fail fast
            val actualAlgorithm = if (algorithm.hasDedicatedMac()) algorithm.innerCipher else algorithm
            return Decryptor(
                initCipher(PlatformCipher.Mode.DECRYPT, actualAlgorithm, key, nonce, aad),
                algorithm,
                authTag,
                macKey
            )
        }
    }

    internal suspend fun decrypt(encryptedData: ByteArray): ByteArray {
        if (algorithm.hasDedicatedMac()) {
            val dedicatedMacInputCalculation = algorithm.macInputCalculation
            val hmacInput = algorithm.dedicatedMacInputCalculation(
                encryptedData,
                platformCipher.nonce ?: byteArrayOf(),
                platformCipher.aad!!
            )
            val macAuthTagTransform = algorithm.macAuthTagTransform
            if (!algorithm.macAuthTagTransform(algorithm.mac.mac(macKey!!, hmacInput).getOrThrow()).contentEquals(authTag))
                throw IllegalArgumentException("Auth Tag mismatch!")
        }
        return platformCipher.doDecrypt(encryptedData, authTag)
    }
}

internal suspend fun <I: NonceTrait<*>, E: SymmetricEncryptionAlgorithm<*, I>> SealedBox<E>.initDecrypt(
    key: ByteArray,
    macKey: ByteArray?,
    aad: ByteArray?
): Decryptor<I, E> =
    Decryptor(
        algorithm,
        key,
        macKey = macKey,
        if (hasNonce()) nonce else null,
        if (isAuthenticated()) authTag else null,
        aad
    )