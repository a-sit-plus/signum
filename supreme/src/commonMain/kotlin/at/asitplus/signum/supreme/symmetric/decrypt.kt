package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthType.Authenticated
import at.asitplus.signum.supreme.mac.mac
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which also holds IV, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function should be avoided, but is required for convenience.
 */
@JvmName("decryptGeneric")
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE") //needed?
@kotlin.internal.LowPriorityInOverloadResolution     //needed?
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

        is AuthType.Unauthenticated -> (this as SealedBox<AuthType.Unauthenticated, *, KeyType.Integrated>).decryptInternal(
            key.secretKey
        )
    }
}

/**
 * Attempts to decrypt this ciphertext (which may hold IV, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the function you typically want to use.
 */
fun <A : AuthType<K>, I : Nonce, K : KeyType> SealedBox<out A, I, out K>.decrypt(
    key: SymmetricKey<out A, I, out K>
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Somebody likes cursed casts!" }
    when (algorithm.authCapability as AuthType<*>) {
        is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, KeyType.Integrated>).decryptInternal(
            key.secretKey
        )

        is Authenticated.WithDedicatedMac<*, *> -> {
            key as SymmetricKey.WithDedicatedMac
            (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, KeyType.WithDedicatedMacKey>).decryptInternal(
                key.secretKey, key.dedicatedMacKey
            )
        }

        is AuthType.Unauthenticated -> (this as SealedBox<AuthType.Unauthenticated, *, KeyType.Integrated>).decryptInternal(
            key.secretKey
        )
    }
}


@JvmName("decryptRawAuthenticated")
private fun SealedBox<Authenticated.Integrated, *, KeyType.Integrated>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

@JvmName("decryptRaw")
private fun SealedBox<AuthType.Unauthenticated, *, KeyType.Integrated>.decryptInternal(
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

    val box: SealedBox<AuthType.Unauthenticated, *, KeyType.Integrated> =
        (if (this is SealedBox.WithNonce<*, *>) (innerCipher as SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, Nonce.Required, KeyType.Integrated>).sealedBox(
            nonce,
            encryptedData
        ) else (innerCipher as SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, Nonce.Without, KeyType.Integrated>).sealedBox(
            encryptedData
        )) as SealedBox<AuthType.Unauthenticated, *, KeyType.Integrated>
    return box.doDecrypt(secretKey)
}