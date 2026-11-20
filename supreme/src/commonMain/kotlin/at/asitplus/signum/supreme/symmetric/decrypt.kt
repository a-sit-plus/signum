package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptGeneric")
suspend fun <E: SymmetricEncryptionAlgorithm<*, *>> SealedBox<E>.decrypt(key: SymmetricKey<E>): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    if (!key.hasDedicatedMacKey()) {
        require(!hasMacKey())
        decryptInternal(
            secretKey = @OptIn(SecretExposure::class) key.secretKey.getOrThrow(),
            authenticatedData = byteArrayOf()
        )
    }
    else {
        require(hasMacKey())
        decrypt(key).getOrThrow()
    }
}

/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptGeneric")
suspend fun SealedBox<*>.decrypt(key: SpecializedSymmetricKey): KmmResult<ByteArray> = key.toSymmetricKey().transform { decrypt(it) }


//required because we don't store MAC info all the way
/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * Do provide [authenticatedData] if required, or else decryption will fail!
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptAuthenticatedIntegrated")
suspend fun <E: SymmetricEncryptionAlgorithm.EncryptThenMAC<*>> SealedBox<E>.decrypt(
    key: SymmetricKey<E>,
    authenticatedData: ByteArray = byteArrayOf()
) = catching {
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
suspend fun <E: SymmetricEncryptionAlgorithm.Authenticated<*>> SealedBox<E>.decrypt(
    key: SymmetricKey<E>,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    if (!key.hasDedicatedMacKey()) {
        require(!hasMacKey())
        decryptInternal(
            @OptIn(SecretExposure::class) key.secretKey.getOrThrow(),
            authenticatedData
        )
    }
    else {
        require(hasMacKey())
        decrypt(key, authenticatedData).getOrThrow()
    }
}


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent mixing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [AES.ECB] key into
 * a [AES.CBC] [SealedBox].
 * In such cases, this function will immediately return a [KmmResult.failure].
 */
suspend fun <E: SymmetricEncryptionAlgorithm.Unauthenticated<*>> SealedBox<E>.decrypt(
    key: SymmetricKey<E>
): KmmResult<ByteArray> = catching {
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    decryptInternal(@OptIn(SecretExposure::class) key.secretKey.getOrThrow())
}


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent mixing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [SymmetricEncryptionAlgorithm.ChaCha20Poly1305] key into
 * a [AES.GCM] [SealedBox].
 * In such cases, this function will immediately return a [KmmResult.failure].
 */
@JvmName("decryptRawAuthenticated")
private suspend fun SealedBox<SymmetricEncryptionAlgorithm.Integrated<*>>.decryptInternal(
    secretKey: ByteArray,
    authenticatedData: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return initDecrypt(secretKey, null, authenticatedData).decrypt(encryptedData)
}

@JvmName("decryptRaw")
private suspend fun SealedBox.Unauthenticated<*>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return initDecrypt(secretKey, null, null).decrypt(encryptedData)
}

private suspend fun SealedBox<SymmetricEncryptionAlgorithm.EncryptThenMAC<*>>.decryptInternal(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
    authenticatedData: ByteArray
): ByteArray = initDecrypt(secretKey, macKey, authenticatedData).decrypt(encryptedData)


//raw data decryption


/**
 * Directly decrypts raw [encryptedData], feeding [nonce] into the decryption process.
 */
@JvmName("decryptRawUnauthedWithNonce")
suspend fun SymmetricKey<SymmetricEncryptionAlgorithm.UnauthenticatedRequiringNonce>.decrypt(
    nonce: ByteArray,
    encryptedData: ByteArray
): KmmResult<ByteArray> = algorithm.sealedBox.withNonce(nonce).from(encryptedData).transform { it.decrypt(this) }


/**
 * Directly decrypts raw [encryptedData].
 */
@JvmName("decryptRawUnauthedNoNonce")
suspend fun SymmetricKey<SymmetricEncryptionAlgorithm.UnauthenticatedWithoutNonce>.decrypt(
    encryptedData: ByteArray
): KmmResult<ByteArray> = algorithm.sealedBox.from(encryptedData).transform { it.decrypt(this) }


/**
 * Directly decrypts raw [encryptedData], feeding [nonce], [authTag], and [authenticatedData] into the decryption process.
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("decryptRawAuthedWithNonce")
suspend fun SymmetricKey<SymmetricEncryptionAlgorithm.AuthenticatedRequiringNonce>.decrypt(
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
suspend fun SymmetricKey<SymmetricEncryptionAlgorithm.AuthenticatedWithoutNonce>.decrypt(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> =
    algorithm.sealedBox.from(encryptedData, authTag).transform { it.decrypt(this, authenticatedData) }