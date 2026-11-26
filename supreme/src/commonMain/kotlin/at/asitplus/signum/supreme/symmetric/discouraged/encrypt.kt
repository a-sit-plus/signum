package at.asitplus.signum.supreme.symmetric.discouraged

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.symmetric.Encryptor
import kotlin.jvm.JvmName


/**
 * Encrypts [data] using the manually specified [nonce]. Check yourself, before you really, really wreck yourself!
 * * [nonce] =  nonce/IV; **NEVER EVER RE-USE THIS!**
 * * [authenticatedData] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [nonce], as it will be added to any  [SealedBox.Authenticated] resulting from an encryption.
 *
 * @throws IllegalArgumentException for invalid parameters
 */
@HazardousMaterials("NEVER re-use a nonce/IV! Have them auto-generated instead!")
@JvmName("encryptAuthenticatedWithNonce")
@Throws(Throwable::class)
@OptIn(SecretExposure::class)
suspend fun <E: SymmetricEncryptionAlgorithm.AuthenticatedRequiringNonce> KeyWithNonceAuthenticating<E>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): SealedBox<E> {
    val second = second
    return Encryptor(
        second.algorithm,
        if (second.hasDedicatedMacKey()) second.encryptionKey else second.secretKey,
        if (second.hasDedicatedMacKey()) second.macKey else second.secretKey,
        first,
        authenticatedData,
    ).encrypt(data)
}

/**
 * Encrypts [data] using the manually specified [nonce]. Check yourself, before you really, really wreck yourself!
 * * [nonce] =  nonce/IV; **NEVER EVER RE-USE THIS!**
 *
 * It is safe to discard the reference to [nonce], as it will be added to any  [SealedBox.Authenticated] resulting from an encryption.
 *
 * @throws IllegalArgumentException for invalid parameters
 */
@HazardousMaterials("NEVER re-use a nonce/IV! Have them auto-generated instead!")
@JvmName("encryptWithNonce")
@Throws(Throwable::class)
@OptIn(SecretExposure::class)
suspend fun <E: SymmetricEncryptionAlgorithm.RequiringNonce<*>> KeyWithNonce<E>.encrypt(
    data: ByteArray
): SealedBox<E> {
    val first = first
    return Encryptor(
        first.algorithm,
        if (first.hasDedicatedMacKey()) first.encryptionKey else first.secretKey,
        if (first.hasDedicatedMacKey()) first.macKey else null,
        second,
        null,
    ).encrypt(data)
}

/**
 * This function can be used to feed a pre-set nonce into encryption functions.
 * This is usually not required, since all algorithms requiting a nonce/IV generate them by default
 * @see at.asitplus.signum.supreme.symmetric.randomNonce
 */
@HazardousMaterials("Nonce/IV re-use can have catastrophic consequences!")
@Throws(Throwable::class)
fun <E: SymmetricEncryptionAlgorithm.RequiringNonce<*>> SymmetricKey<E>.andPredefinedNonce(nonce: ByteArray): KeyWithNonce<E> {
    require(nonce.size == algorithm.nonceSize.bytes.toInt()) { "$algorithm requires a nonce of size ${algorithm.nonceSize}!" }
    return KeyWithNonce(this, nonce)
}

/**
 * This function can be used to feed a pre-set nonce into encryption functions.
 * This is usually not required, since all algorithms requiting a nonce/IV generate them by default
 * @see at.asitplus.signum.supreme.symmetric.randomNonce
 */
@HazardousMaterials("Nonce/IV re-use can have catastrophic consequences!")
@JvmName("authedKeyWithNonce")
@Throws(Throwable::class)
fun <E: SymmetricEncryptionAlgorithm.AuthenticatedRequiringNonce> SymmetricKey<E>.andPredefinedNonce(
    nonce: ByteArray
): KeyWithNonceAuthenticating<E> {
    require(nonce.size == algorithm.nonceSize.bytes.toInt()) { "$algorithm requires a nonce of size ${algorithm.nonceSize}!" }
    return KeyWithNonceAuthenticating(nonce, this)
}

private typealias KeyWithNonce<E> = Pair<SymmetricKey<E>, ByteArray>
//first and second are deliberately swapped to avoid mixups
private typealias KeyWithNonceAuthenticating<E> = Pair<ByteArray, SymmetricKey<E>>


val KeyWithNonceAuthenticating<*>.nonce: ByteArray @JvmName("nonceAuthenticating") get() = first
val KeyWithNonce<*>.nonce: ByteArray get() = second