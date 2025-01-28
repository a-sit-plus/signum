package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
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
fun SealedBox<*, *, *>.decrypt(key: SymmetricKey<*, *, *>) = catching {
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
fun <A : AuthCapability<K>, I : NonceTrait, K : KeyType> SealedBox<A, I, K>.decrypt(
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
    authenticatedData: ByteArray? = null
): KmmResult<ByteArray> =
    algorithm.sealedBoxFrom(nonce, encryptedData, authTag, authenticatedData).transform { it.decrypt(this) }

/**
 * Directly decrypts raw [encryptedData], feeding [authTag], and [authenticatedData] into the decryption process.
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("decryptRawAuthedNoNonce")
fun SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Without, *>.decrypt(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<ByteArray> =
    algorithm.sealedBoxFrom(encryptedData, authTag, authenticatedData).transform { it.decrypt(this) }