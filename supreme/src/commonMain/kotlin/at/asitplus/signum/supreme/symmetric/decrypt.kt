package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AECapability.Authenticated
import at.asitplus.signum.supreme.mac.mac
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which also holds IV, and in case of an authenticated ciphertext, AAD and auth tag) using the provided [key].
 * This is the function you typically want to use.
 */
fun <A : AECapability> SealedBox<A, Nonce.Required, SymmetricEncryptionAlgorithm<A, Nonce.Required>>.decrypt(key: SymmetricKey<in A, Nonce.Required>): KmmResult<ByteArray> =
    catching {
        require(algorithm == key.algorithm) { "Somebody likes cursed casts!" }
        when (algorithm.cipher as AECapability) {
            is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<AECapability.Authenticated.Integrated, *>>).decryptInternal(
                key.secretKey
            )

            is Authenticated.WithDedicatedMac<*, *> -> {
                key as SymmetricKey.WithDedicatedMac
                (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).decryptInternal(
                    key.secretKey, key.dedicatedMacKey
                )
            }

            is AECapability.Unauthenticated -> (this as SealedBox<AECapability.Unauthenticated, *, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>>).decryptInternal(
                key.secretKey
            )
        }
    }


@JvmName("decryptRawAuthenticated")
private fun SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<AECapability.Authenticated.Integrated, *>>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

@JvmName("decryptRaw")
private fun SealedBox<AECapability.Unauthenticated, *, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

/**
 * Attempts to decrypt this ciphertext using the provided raw [secretKey].
 * If no [macKey] is provided, [secretKey] will be used as MAC key.
 * [dedicatedMacInputCalculation] can be used to override the [DefaultDedicatedMacInputCalculation] used to compute MAC input.
 */
private fun SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>.decryptInternal(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
): ByteArray {
    val iv: ByteArray? = if (this is SealedBox.WithNonce<*, *>) nonce else null
    val aad = authenticatedData
    val authTag = authTag

    val algorithm = algorithm
    val innerCipher = algorithm.cipher.innerCipher
    val mac = algorithm.cipher.mac
    val dedicatedMacInputCalculation = algorithm.cipher.dedicatedMacInputCalculation
    val hmacInput = mac.dedicatedMacInputCalculation(encryptedData, iv, aad)

    if (!(mac.mac(macKey, hmacInput).getOrThrow().contentEquals(authTag)))
        throw IllegalArgumentException("Auth Tag mismatch!")

    val box: SealedBox<AECapability.Unauthenticated, *, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>> =
        (if (this is SealedBox.WithNonce<*, *>) (innerCipher as SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Required>).sealedBox(
            nonce,
            encryptedData
        ) else (innerCipher as SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Without>).sealedBox(
            encryptedData
        )) as SealedBox<AECapability.Unauthenticated, *, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>>
    return box.doDecrypt(secretKey)
}