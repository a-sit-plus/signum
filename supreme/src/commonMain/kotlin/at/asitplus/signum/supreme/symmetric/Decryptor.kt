package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.mac.mac

//needs no generics, because decrypt goes from bytes to bytes
internal class Decryptor(
    val platformCipher: PlatformCipher<*, *, *>,
    val algorithm: SymmetricEncryptionAlgorithm<*, *, *>,
    val authTag: ByteArray?,
    val macKey: ByteArray?
) {
    companion object {
        suspend operator fun invoke(
            algorithm: SymmetricEncryptionAlgorithm<*, *, *>,
            key: ByteArray,
            macKey: ByteArray?,
            nonce: ByteArray?,
            authTag: ByteArray?,
            aad: ByteArray?
        ): Decryptor {
            //while ir could be argued that we should not check here. we are only calling this chained with decrypt(), so it is fine to fail fast
            val actualAlgorithm = if (algorithm.hasDedicatedMac()) {
                algorithm.innerCipher
            } else algorithm
            return Decryptor(
                initCipher(PlatformCipher.Mode.DECRYPT, actualAlgorithm, key, nonce, aad),
                algorithm,
                authTag,
                macKey
            )
        }
    }

    internal suspend fun decrypt(encryptedData: ByteArray): ByteArray {
        if(algorithm is SymmetricEncryptionAlgorithm.AES && algorithm.mode == BlockCipher.ModeOfOperation.ECB){
            //Fail early for all platforms
            if (encryptedData.size % 16 != 0) throw CryptoOperationFailed("data must be aligned to block size")
        }


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

internal suspend fun SealedBox<*, *, *>.initDecrypt(
    key: ByteArray,
    macKey: ByteArray?,
    aad: ByteArray?
): Decryptor =
    Decryptor(
        algorithm,
        key,
        macKey = macKey,
        if (hasNonce()) nonce else null,
        if (isAuthenticated()) authTag else null,
        aad
    )