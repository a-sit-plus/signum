package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.*
import kotlin.jvm.JvmName

/**
 * Encrypts [data] and automagically generates a fresh nonce/IV if required by the cipher.
 *
 * @throws IllegalArgumentException for invalid parameters
 */
@JvmName("encryptWithAutoGenIV")
@Throws(Throwable::class)
suspend fun <E: SymmetricEncryptionAlgorithm<*, *>> SymmetricKey<E>.encrypt(
    data: ByteArray
): SealedBox<E> =
    @OptIn(SecretExposure::class)
    Encryptor(
        algorithm,
        if (this.hasDedicatedMacKey()) encryptionKey else secretKey,
        if (this.hasDedicatedMacKey()) macKey else null,
        aad = null
    ).encrypt(data)


/**
 * Encrypts [data] and automagically generates a fresh nonce/IV if required by the cipher.
 *
 * @param authenticatedData Additional data to be authenticated (i.e. fed into the auth tag generation) but not encrypted.
 * -
 * It is safe to discard the reference to this data, as the [SealedBox] resulting from this operation will carry the
 * corresponding type information.
 *
 * @throws IllegalArgumentException for invalid parameters
 */
@JvmName("encryptAuthenticated")
@Throws(Throwable::class)
suspend fun <E: SymmetricEncryptionAlgorithm.Authenticated<*>> SymmetricKey<E>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): SealedBox<E> =
    @OptIn(SecretExposure::class)
    Encryptor(
        algorithm,
        if (this.hasDedicatedMacKey()) encryptionKey else secretKey,
        if (this.hasDedicatedMacKey()) macKey else null,
        aad = authenticatedData,
    ).encrypt(data)

@Throws(Throwable::class)
suspend fun SpecializedSymmetricKey.encrypt(data: ByteArray, authenticatedData: ByteArray? = null): SealedBox<*> {
    val key = toSymmetricKey()
    return if (key.isAuthenticated()) key.encrypt(data, authenticatedData)
    else {
        require(authenticatedData == null) { "Cannot specify AAD with non-AAD cipher" }
        key.encrypt(data)
    }
}
