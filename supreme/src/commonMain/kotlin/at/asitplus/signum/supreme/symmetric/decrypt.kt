package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import at.asitplus.signum.internals.ImplementationError
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptGeneric")
suspend fun SealedBox<*, *>.decrypt(key: SymmetricKey<*, *>): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    @Suppress("UNCHECKED_CAST")
    when (algorithm.authCapability) {
        is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *>).decryptInternal(
            secretKey = @OptIn(SecretExposure::class) (key as SymmetricKey.Integrated).secretKey.getOrThrow(),
            authenticatedData = byteArrayOf()
        )

        is Authenticated.WithDedicatedMac -> {
            key as SymmetricKey.WithDedicatedMac
            (this as SealedBox<Authenticated.WithDedicatedMac, *>).decryptInternal(
                secretKey = @OptIn(SecretExposure::class) key.encryptionKey.getOrThrow(),
                macKey = @OptIn(SecretExposure::class) key.macKey.getOrThrow(),
                authenticatedData = byteArrayOf()
            )
        }

        is AuthCapability.Unauthenticated -> (this as SealedBox<AuthCapability.Unauthenticated, *>).decryptInternal(
            secretKey = @OptIn(SecretExposure::class) (key as SymmetricKey.Integrated).secretKey.getOrThrow()
        )
    }
}

/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptGeneric")
suspend fun SealedBox<*, *>.decrypt(key: SpecializedSymmetricKey): KmmResult<ByteArray> = key.toSymmetricKey().transform { decrypt(it) }


//required because we don't store MAC info all the way
/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * Do provide [authenticatedData] if required, or else decryption will fail!
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptAuthenticatedIntegrated")
suspend fun <I : NonceTrait> SealedBox<Authenticated.WithDedicatedMac, I>.decrypt(
    key: SymmetricKey.WithDedicatedMac<*>,
    authenticatedData: ByteArray = byteArrayOf()
) = catching {
    @Suppress("UNCHECKED_CAST")
    decryptInternal(
        @OptIn(SecretExposure::class)
        key.encryptionKey.getOrThrow(),
        @OptIn(SecretExposure::class)
        key.macKey.getOrThrow(),
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
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
@JvmName("decryptAuthenticatedGeneric")
suspend fun <A : AuthCapability.Authenticated, I : NonceTrait> SealedBox<A, I>.decrypt(
    key: SymmetricKey<A, I>,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    @Suppress("UNCHECKED_CAST")
    when (algorithm.authCapability) {
        is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *>).decryptInternal(
            @OptIn(SecretExposure::class) (key as SymmetricKey.Integrated).secretKey.getOrThrow(),
            authenticatedData
        )

        is Authenticated.WithDedicatedMac -> {
            key as SymmetricKey.WithDedicatedMac
            (this as SealedBox<Authenticated.WithDedicatedMac, *>).decryptInternal(
                @OptIn(SecretExposure::class) key.encryptionKey.getOrThrow(),
                @OptIn(SecretExposure::class) key.macKey.getOrThrow(),
                authenticatedData
            )
        }
    }
}


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent mixing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [AES.ECB] key into
 * a [AES.CBC] [SealedBox].
 * In such cases, this function will immediately return a [KmmResult.failure].
 */
suspend fun <I : NonceTrait> SealedBox<AuthCapability.Unauthenticated, I>.decrypt(
    key: SymmetricKey<AuthCapability.Unauthenticated, I>
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    @Suppress("UNCHECKED_CAST")
    (this as SealedBox<AuthCapability.Unauthenticated, *>).decryptInternal(
        @OptIn(SecretExposure::class) (key as SymmetricKey.Integrated).secretKey.getOrThrow()
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
private suspend fun SealedBox<Authenticated.Integrated, *>.decryptInternal(
    secretKey: ByteArray,
    authenticatedData: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return initDecrypt(secretKey, null, authenticatedData).decrypt(encryptedData)
}

@JvmName("decryptRaw")
private suspend fun SealedBox<AuthCapability.Unauthenticated, *>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return initDecrypt(secretKey, null, null).decrypt(encryptedData)
}

private suspend fun SealedBox<Authenticated.WithDedicatedMac, *>.decryptInternal(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
    authenticatedData: ByteArray
): ByteArray {
    return initDecrypt(secretKey, macKey, authenticatedData).decrypt(encryptedData)
}


//raw data decryption


/**
 * Directly decrypts raw [encryptedData], feeding [nonce] into the decryption process.
 */
@JvmName("decryptRawUnauthedWithNonce")
suspend fun SymmetricKey<AuthCapability.Unauthenticated, NonceTrait.Required>.decrypt(
    nonce: ByteArray,
    encryptedData: ByteArray
): KmmResult<ByteArray> = algorithm.sealedBox.withNonce(nonce).from(encryptedData).transform { it.decrypt(this) }


/**
 * Directly decrypts raw [encryptedData].
 */
@JvmName("decryptRawUnauthedNoNonce")
suspend fun SymmetricKey<AuthCapability.Unauthenticated, NonceTrait.Without>.decrypt(
    encryptedData: ByteArray
): KmmResult<ByteArray> = algorithm.sealedBox.from(encryptedData).transform { it.decrypt(this) }


/**
 * Directly decrypts raw [encryptedData], feeding [nonce], [authTag], and [authenticatedData] into the decryption process.
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("decryptRawAuthedWithNonce")
suspend fun <A : AuthCapability.Authenticated> SymmetricKey<A, NonceTrait.Required>.decrypt(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> =
    algorithm.sealedBox.withNonce(nonce).from(encryptedData, authTag).transform { it.decrypt(this, authenticatedData) }

/**
 * Directly decrypts raw [encryptedData], feeding [authTag], and [authenticatedData] into the decryption process.
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("decryptRawAuthedNoNonce")
suspend fun <A : AuthCapability.Authenticated> SymmetricKey<A, NonceTrait.Without>.decrypt(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> =
    algorithm.sealedBox.from(encryptedData, authTag).transform {
        @Suppress("UNCHECKED_CAST")
        it.decrypt(
            this as SymmetricKey<AuthCapability.Authenticated, NonceTrait.Without>,
            authenticatedData
        )
    }