package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthType.Authenticated
import at.asitplus.signum.supreme.mac.mac
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which also holds IV, and in case of an authenticated ciphertext, AAD and auth tag) using the provided [key].
 * This is the function you typically want to use.
 */
fun <K : KeyType, A : AuthType<K>> SealedBox<A, Nonce.Required, SymmetricEncryptionAlgorithm<A, Nonce.Required>>.decrypt(
    key: SymmetricKey<in A, Nonce.Required, out K>
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Somebody likes cursed casts!" }
    when (algorithm.authCapability as AuthType<*>) {
        is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<AuthType.Authenticated.Integrated, *>>).decryptInternal(
            key.secretKey
        )

        is Authenticated.WithDedicatedMac<*, *> -> {
            key as SymmetricKey.WithDedicatedMac
            (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).decryptInternal(
                key.secretKey, key.dedicatedMacKey
            )
        }

        is AuthType.Unauthenticated -> (this as SealedBox<AuthType.Unauthenticated, *, SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, *>>).decryptInternal(
            key.secretKey
        )
    }
}


@JvmName("decryptRawAuthenticated")
private fun SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<AuthType.Authenticated.Integrated, *>>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

@JvmName("decryptRaw")
private fun SealedBox<AuthType.Unauthenticated, *, SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, *>>.decryptInternal(
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
    val innerCipher = algorithm.authCapability.innerCipher
    val mac = algorithm.authCapability.mac
    val dedicatedMacInputCalculation = algorithm.authCapability.dedicatedMacInputCalculation
    val hmacInput = mac.dedicatedMacInputCalculation(encryptedData, iv ?: byteArrayOf(), aad ?: byteArrayOf())

    if (!(mac.mac(macKey, hmacInput).getOrThrow().contentEquals(authTag)))
        throw IllegalArgumentException("Auth Tag mismatch!")

    val box: SealedBox<AuthType.Unauthenticated, *, SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, *>> =
        (if (this is SealedBox.WithNonce<*, *>) (innerCipher as SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, Nonce.Required>).sealedBox(
            nonce,
            encryptedData
        ) else (innerCipher as SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, Nonce.Without>).sealedBox(
            encryptedData
        )) as SealedBox<AuthType.Unauthenticated, *, SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, *>>
    return box.doDecrypt(secretKey)
}