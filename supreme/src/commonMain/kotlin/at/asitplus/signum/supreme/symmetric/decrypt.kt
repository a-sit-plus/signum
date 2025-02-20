package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.ImplementationError
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import at.asitplus.signum.supreme.mac.mac
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptGeneric")
fun SealedBox<*, *, *>.decrypt(key: SymmetricKey<*, *, *>): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    @Suppress("UNCHECKED_CAST")
    when (algorithm.authCapability) {
        is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, KeyType.Integrated>).decryptInternal(
            (key as SymmetricKey.Integrated).secretKey, byteArrayOf()
        )

        is Authenticated.WithDedicatedMac<*, *> -> {
            key as SymmetricKey.WithDedicatedMac
            (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, KeyType.WithDedicatedMacKey>).decryptInternal(
                key.encryptionKey, key.macKey, byteArrayOf()
            )
        }

        is AuthCapability.Unauthenticated -> (this as SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated>).decryptInternal(
            (key as SymmetricKey.Integrated).secretKey
        )
    }
}




//required because we don't store MAC info all the way
/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * Do provide [authenticatedData] if required, or else decryption will fail!
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptAuthenticatedIntegrated")
fun <I: NonceTrait, M: MAC>SealedBox<AuthCapability.Authenticated.WithDedicatedMac<M, I>,I, KeyType.WithDedicatedMacKey>.decrypt(
    key: SymmetricKey.WithDedicatedMac<*>,
    authenticatedData: ByteArray = byteArrayOf()
) = catching {
    (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, KeyType.WithDedicatedMacKey>).decryptInternal(
        key.encryptionKey,
        key.macKey,
        authenticatedData
    )
}

/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * Do provide [authenticatedData] if required, or else decryption will fail!
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptAuthenticatedGeneric")
fun <A : AuthCapability.Authenticated<out K>, K : KeyType> SealedBox<A, *, out K>.decrypt(
    key: SymmetricKey<A, *, out K>,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    @Suppress("UNCHECKED_CAST")
    when (algorithm.authCapability) {
        is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, KeyType.Integrated>).decryptInternal(
            (key as SymmetricKey.Integrated).secretKey, authenticatedData
        )

        is Authenticated.WithDedicatedMac<*, *> -> {
            key as SymmetricKey.WithDedicatedMac
            (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, KeyType.WithDedicatedMacKey>).decryptInternal(
                key.encryptionKey, key.macKey, authenticatedData
            )
        }

        else -> throw ImplementationError("Authenticated Decryption")
    }
}


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent mixing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [AES.ECB] key into
 * a [AES.CBC] [SealedBox].
 * In such cases, this function will immediately return a [KmmResult.failure].
 */
fun <I : NonceTrait> SealedBox<AuthCapability.Unauthenticated, I, KeyType.Integrated>.decrypt(
    key: SymmetricKey<AuthCapability.Unauthenticated, I, KeyType.Integrated>
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    @Suppress("UNCHECKED_CAST")
    (this as SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated>).decryptInternal(
        (key as SymmetricKey.Integrated).secretKey
    )

}


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent mixing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [SymmetricEncryptionAlgorithm.ChaCha20Poly1305] key into
 * a [AES.GCM] [SealedBox].
 * In such cases, this function will immediately return a [KmmResult.failure].
 */
@JvmName("decryptRawAuthenticated")
private fun SealedBox<Authenticated.Integrated, *, out KeyType.Integrated>.decryptInternal(
    secretKey: ByteArray,
    authenticatedData: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecryptAEAD(secretKey, authenticatedData)
}

@JvmName("decryptRaw")
private fun SealedBox<AuthCapability.Unauthenticated, *, out KeyType.Integrated>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

private fun SealedBox<Authenticated.WithDedicatedMac<*, *>, *, out KeyType.WithDedicatedMacKey>.decryptInternal(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
    authenticatedData: ByteArray
): ByteArray {
    require(this.isAuthenticated())
    val iv: ByteArray? = if (this is SealedBox.WithNonce<*, *>) nonce else null
    val authTag = authTag

    val algorithm = algorithm
    val innerCipher = algorithm.authCapability.innerCipher
    val mac = algorithm.authCapability.mac
    val dedicatedMacInputCalculation = algorithm.authCapability.dedicatedMacInputCalculation
    val hmacInput = mac.dedicatedMacInputCalculation(encryptedData, iv ?: byteArrayOf(), authenticatedData)
    val transform = algorithm.authCapability.dedicatedMacAuthTagTransform
    if (!algorithm.authCapability.transform(mac.mac(macKey, hmacInput).getOrThrow()).contentEquals(authTag))
        throw IllegalArgumentException("Auth Tag mismatch!")

    @Suppress("UNCHECKED_CAST") val box: SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated> =
        (if (this is SealedBox.WithNonce<*, *>) (innerCipher as SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>).sealedBoxFrom(
            nonce,
            encryptedData
        ) else (innerCipher as SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>).sealedBoxFrom(
            encryptedData
        )).getOrThrow() as SealedBox<AuthCapability.Unauthenticated, *, KeyType.Integrated>
    return box.doDecrypt(secretKey)
}


//raw data decryption


/**
 * Directly decrypts raw [encryptedData], feeding [nonce] into the decryption process.
 */
@JvmName("decryptRawUnauthedWithNonce")
fun SymmetricKey<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>.decrypt(
    nonce: ByteArray,
    encryptedData: ByteArray
): KmmResult<ByteArray> = algorithm.sealedBoxFrom(nonce, encryptedData).transform { it.decrypt(this) }


/**
 * Directly decrypts raw [encryptedData].
 */
@JvmName("decryptRawUnauthedNoNonce")
fun SymmetricKey<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>.decrypt(
    encryptedData: ByteArray
): KmmResult<ByteArray> = algorithm.sealedBoxFrom(encryptedData).transform { it.decrypt(this) }


/**
 * Directly decrypts raw [encryptedData], feeding [nonce], [authTag], and [authenticatedData] into the decryption process.
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("decryptRawAuthedWithNonce")
fun SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *>.decrypt(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> =
    algorithm.sealedBoxFrom(nonce, encryptedData, authTag).transform { it.decrypt(this, authenticatedData) }

/**
 * Directly decrypts raw [encryptedData], feeding [authTag], and [authenticatedData] into the decryption process.
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("decryptRawAuthedNoNonce")
fun SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Without, *>.decrypt(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> =
    algorithm.sealedBoxFrom(encryptedData, authTag).transform { it.decrypt(this, authenticatedData) }