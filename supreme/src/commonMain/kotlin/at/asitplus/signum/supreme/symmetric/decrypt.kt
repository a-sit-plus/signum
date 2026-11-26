package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import kotlin.jvm.JvmName

private fun SealedBox<*>.requireSupportedAlgorithms(key: SymmetricKey<*>) {
    algorithm.requireSupremeSymmetricBuiltin()
    key.algorithm.requireSupremeSymmetricBuiltin()
}

/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptGeneric")
@Throws(Throwable::class)
suspend fun <E: SymmetricEncryptionAlgorithm<*, *>> SealedBox<E>.decrypt(key: SymmetricKey<E>): ByteArray {
    requireSupportedAlgorithms(key)
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    return if (!key.hasDedicatedMacKey()) {
        require(!hasMacKey())
        decryptInternal(
            secretKey = @OptIn(SecretExposure::class) key.secretKey,
            authenticatedData = byteArrayOf()
        )
    }
    else {
        require(hasMacKey())
        decrypt(key)
    }
}

/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptGeneric")
@Throws(Throwable::class)
suspend fun SealedBox<*>.decrypt(key: SpecializedSymmetricKey): ByteArray = decrypt(key.toSymmetricKey())


//required because we don't store MAC info all the way
/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * Do provide [authenticatedData] if required, or else decryption will fail!
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptAuthenticatedIntegrated")
@Throws(Throwable::class)
suspend fun <E: SymmetricEncryptionAlgorithm.EncryptThenMAC<*>> SealedBox<E>.decrypt(
    key: SymmetricKey<E>,
    authenticatedData: ByteArray = byteArrayOf()
): ByteArray {
    requireSupportedAlgorithms(key)
    return decryptInternal(
        @OptIn(SecretExposure::class)
        key.encryptionKey,
        @OptIn(SecretExposure::class)
        key.macKey,
        authenticatedData
    )
}

/**
 * Decrypts an integrated AEAD sealed box with an integrated AEAD [key].
 * Pass the same [authenticatedData] that was used for encryption.
 */
@JvmName("decryptAuthenticatedGeneric")
@Throws(Throwable::class)
suspend fun <E : SymmetricEncryptionAlgorithm.AuthenticatedIntegrated<*>> SealedBox<E>.decrypt(
    key: SymmetricKey<E>,
    authenticatedData: ByteArray = byteArrayOf()
): ByteArray = decryptAuthenticated(key, authenticatedData)

private suspend fun SealedBox.Authenticated<*>.decryptAuthenticated(
    key: SymmetricKey.Authenticating<*>,
    authenticatedData: ByteArray
): ByteArray {
    requireSupportedAlgorithms(key)
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    return if (!key.hasDedicatedMacKey()) {
        require(!hasMacKey())
        decryptInternal(
            @OptIn(SecretExposure::class) key.secretKey,
            authenticatedData
        )
    }
    else {
        require(hasMacKey())
        decrypt(key, authenticatedData)
    }
}


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent mixing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [AES.ECB] key into
 * a [AES.CBC] [SealedBox].
 * In such cases, this function throws [IllegalArgumentException].
 */
@Throws(Throwable::class)
suspend fun <E: SymmetricEncryptionAlgorithm.Unauthenticated<*>> SealedBox<E>.decrypt(
    key: SymmetricKey<E>
): ByteArray {
    requireSupportedAlgorithms(key)
    require(algorithm == key.algorithm) { "Algorithm mismatch! expected: $algorithm, actual: ${key.algorithm}" }
    return decryptInternal(@OptIn(SecretExposure::class) key.secretKey)
}


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This constrains the [key]'s characteristics to the characteristics of the [SealedBox] to decrypt.
 * It does not, however, prevent mixing up different encryption algorithms with the same characteristics. I.e., it is possible to feed a [SymmetricEncryptionAlgorithm.ChaCha20Poly1305] key into
 * a [AES.GCM] [SealedBox].
 * In such cases, this function throws [IllegalArgumentException].
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
@Throws(Throwable::class)
suspend fun SymmetricKey<SymmetricEncryptionAlgorithm.UnauthenticatedRequiringNonce>.decrypt(
    nonce: ByteArray,
    encryptedData: ByteArray
): ByteArray = algorithm.requireSupremeSymmetricBuiltin().sealedBox.withNonce(nonce).from(encryptedData).decrypt(this)


/**
 * Directly decrypts raw [encryptedData].
 */
@JvmName("decryptRawUnauthedNoNonce")
@Throws(Throwable::class)
suspend fun SymmetricKey<SymmetricEncryptionAlgorithm.UnauthenticatedWithoutNonce>.decrypt(
    encryptedData: ByteArray
): ByteArray = algorithm.requireSupremeSymmetricBuiltin().sealedBox.from(encryptedData).decrypt(this)


/**
 * Directly decrypts raw [encryptedData], feeding [nonce], [authTag], and [authenticatedData] into the decryption process.
 * @throws IllegalArgumentException on illegal auth tag length
 */
@JvmName("decryptRawAuthedWithNonce")
@Throws(Throwable::class)
suspend fun SymmetricKey<SymmetricEncryptionAlgorithm.AuthenticatedRequiringNonce>.decrypt(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray = byteArrayOf()
): ByteArray =
    algorithm.requireSupremeSymmetricBuiltin().sealedBox.withNonce(nonce).from(encryptedData, authTag)
        .decryptAuthenticated(this, authenticatedData)

/**
 * Directly decrypts raw [encryptedData], feeding [authTag], and [authenticatedData] into the decryption process.
 * @throws IllegalArgumentException on illegal auth tag length
 */
@JvmName("decryptRawAuthedNoNonce")
@Throws(Throwable::class)
suspend fun SymmetricKey<SymmetricEncryptionAlgorithm.AuthenticatedWithoutNonce>.decrypt(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray = byteArrayOf()
): ByteArray =
    algorithm.requireSupremeSymmetricBuiltin().sealedBox.from(encryptedData, authTag)
        .decryptAuthenticated(this, authenticatedData)
