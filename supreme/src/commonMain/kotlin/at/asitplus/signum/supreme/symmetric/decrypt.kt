package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.ImplementationError
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which may also hold an IV/nonce, and in case of an authenticated ciphertext, authenticated data and auth tag) using the provided [key].
 * This is the generic, untyped decryption function for convenience.
 * **Compared to its narrower-typed cousins is possible to mismatch the characteristics of
 * [key] and [SealedBox].**
 */
@JvmName("decryptGeneric")
suspend fun SealedBox<*, *, *>.decrypt(key: SymmetricKey<*, *, *>): KmmResult<ByteArray> = catching {
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
suspend fun <I : NonceTrait, M : MessageAuthenticationCode> SealedBox<AuthCapability.Authenticated.WithDedicatedMac<M, I>, I, KeyType.WithDedicatedMacKey>.decrypt(
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
suspend fun <A : AuthCapability.Authenticated<out K>,I: NonceTrait, K : KeyType> SealedBox<A, I, out K>.decrypt(
    key: SymmetricKey<A, I, out K>,
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
suspend fun <I : NonceTrait> SealedBox<AuthCapability.Unauthenticated, I, KeyType.Integrated>.decrypt(
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
private suspend fun SealedBox<Authenticated.Integrated, *, out KeyType.Integrated>.decryptInternal(
    secretKey: ByteArray,
    authenticatedData: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return initDecrypt(secretKey, null, authenticatedData).decrypt(encryptedData)
}

@JvmName("decryptRaw")
private suspend fun SealedBox<AuthCapability.Unauthenticated, *, out KeyType.Integrated>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return initDecrypt(secretKey, null, null).decrypt(encryptedData)
}

private suspend fun SealedBox<Authenticated.WithDedicatedMac<*, *>, *, out KeyType.WithDedicatedMacKey>.decryptInternal(
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
suspend fun SymmetricKey<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>.decrypt(
    nonce: ByteArray,
    encryptedData: ByteArray
): KmmResult<ByteArray> = algorithm.sealedBox.withNonce(nonce).from(encryptedData).transform { it.decrypt(this) }


/**
 * Directly decrypts raw [encryptedData].
 */
@JvmName("decryptRawUnauthedNoNonce")
suspend fun SymmetricKey<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>.decrypt(
    encryptedData: ByteArray
): KmmResult<ByteArray> = algorithm.sealedBox.from(encryptedData).transform { it.decrypt(this) }


/**
 * Directly decrypts raw [encryptedData], feeding [nonce], [authTag], and [authenticatedData] into the decryption process.
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("decryptRawAuthedWithNonce")
suspend fun <A : AuthCapability.Authenticated<*>> SymmetricKey<A, NonceTrait.Required, *>.decrypt(
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
suspend fun <A : AuthCapability.Authenticated<*>> SymmetricKey<A, NonceTrait.Without, *>.decrypt(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray = byteArrayOf()
): KmmResult<ByteArray> =
    algorithm.sealedBox.from(encryptedData, authTag).transform {
        it.decrypt(
            @Suppress("UNCHECKED_CAST")
            this as SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Without, *>,
            authenticatedData
        )
    }