package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import at.asitplus.signum.supreme.mac.mac
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.*
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * Compared to its narrower-typed cousins, this is more likely to fail, because it is possible to mismatch the characteristics of
 * [key] and [SealedBox].
 */
@JvmName("decryptGeneric")
fun SealedBox<*,*,*>.decrypt(key: SymmetricKey<*,*,*>)  = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    when (algorithm.authCapability) {
        is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, KeyType.Integrated>).decryptInternal(
            key.secretKey
        )

        is Authenticated.WithDedicatedMac<*, *> -> {
            key as SymmetricKey.WithDedicatedMac
            (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, KeyType.WithDedicatedMacKey>).decryptInternal(
                key.secretKey, key.dedicatedMacKey
            )
        }

        is AuthCapability.Unauthenticated -> (this as SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated>).decryptInternal(
            key.secretKey
        )
    }
}

/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent maxing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [AES.ECB] key into
 * a [AES.CBC] [SealedBox].
 * In such cases, this function will immediately return a [KmmResult.failure].
 */
fun <A : AuthCapability<K>, I : WithNonce, K : KeyType> SealedBox< A, I, K>.decrypt(
    key: SymmetricKey<A, I, K>
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Somebody likes cursed casts!" }
    when (algorithm.authCapability as AuthCapability<*>) {
        is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, KeyType.Integrated>).decryptInternal(
            key.secretKey
        )

        is Authenticated.WithDedicatedMac<*, *> -> {
            key as SymmetricKey.WithDedicatedMac
            (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, KeyType.WithDedicatedMacKey>).decryptInternal(
                key.secretKey, key.dedicatedMacKey
            )
        }

        is AuthCapability.Unauthenticated -> (this as SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated>).decryptInternal(
            key.secretKey
        )
    }
}


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent maxing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [SymmetricEncryptionAlgorithm.ChaCha20Poly1305] key into
 * a [AES.GCM] [SealedBox].
 * In such cases, this function will immediately return a [KmmResult.failure].
 */
@JvmName("decryptRawAuthenticated")
private fun SealedBox<Authenticated.Integrated, *, KeyType.Integrated>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

@JvmName("decryptRaw")
private fun SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

private fun SealedBox<Authenticated.WithDedicatedMac<*, *>, *, KeyType.WithDedicatedMacKey>.decryptInternal(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
): ByteArray {
    require(this.isAuthenticated())
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

    val box: SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated> =
        (if (this is SealedBox.WithNonce<*, *>) (innerCipher as SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, WithNonce.Yes, KeyType.Integrated>).sealedBoxFrom(
            nonce,
            encryptedData
        ) else (innerCipher as SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, WithNonce.No, KeyType.Integrated>).sealedBoxFrom(
            encryptedData
        )).getOrThrow() as SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated>
    return box.doDecrypt(secretKey)
}