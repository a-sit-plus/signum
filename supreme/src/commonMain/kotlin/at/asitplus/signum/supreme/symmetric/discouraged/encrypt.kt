package at.asitplus.signum.supreme.symmetric.discouraged

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
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
suspend fun <K : KeyType, A : AuthCapability.Authenticated<out K>> KeyWithNonceAuthenticating<A, out K>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): SealedBox<A, NonceTrait.Required, out K> =
    @OptIn(SecretExposure::class)
    Encryptor(
        second.algorithm,
        if (second.hasDedicatedMacKey()) (second as WithDedicatedMac<NonceTrait.Required>).encryptionKey else (second as SymmetricKey.Integrated<out A, NonceTrait.Required>).secretKey,
        if (second.hasDedicatedMacKey()) (second as WithDedicatedMac<NonceTrait.Required>).macKey else (second as SymmetricKey.Integrated<out A, NonceTrait.Required>).secretKey,
        first,
        authenticatedData,
    ).encrypt(data) as SealedBox<A, NonceTrait.Required, K>

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
suspend fun <K : KeyType, A : AuthCapability<out K>> KeyWithNonce<A, out K>.encrypt(
    data: ByteArray
): SealedBox.WithNonce<A, out K> =
    @OptIn(SecretExposure::class)
    Encryptor(
        first.algorithm,
        if (first.hasDedicatedMacKey()) (first as WithDedicatedMac<NonceTrait.Required>).encryptionKey else (first as SymmetricKey.Integrated<out A, NonceTrait.Required>).secretKey,
        if (first.hasDedicatedMacKey()) (first as WithDedicatedMac<NonceTrait.Required>).macKey else null,
        second,
        null,
    ).encrypt(data) as SealedBox.WithNonce<A, out K>

/**
 * This function can be used to feed a pre-set nonce into encryption functions.
 * This is usually not required, since all algorithms requiting a nonce/IV generate them by default
 * @see at.asitplus.signum.supreme.symmetric.randomNonce
 */
@HazardousMaterials("Nonce/IV re-use can have catastrophic consequences!")
@Throws(Throwable::class)
fun <K : KeyType, A : AuthCapability<out K>> SymmetricKey<A, NonceTrait.Required, out K>.andPredefinedNonce(nonce: ByteArray): KeyWithNonce<A, out K> {
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
fun <K : KeyType, A : AuthCapability.Authenticated<out K>> SymmetricKey<out A, NonceTrait.Required, out K>.andPredefinedNonce(
    nonce: ByteArray
): KeyWithNonceAuthenticating<A, out K> {
    require(nonce.size == algorithm.nonceSize.bytes.toInt()) { "$algorithm requires a nonce of size ${algorithm.nonceSize}!" }
    return KeyWithNonceAuthenticating(nonce, this)
}

private typealias KeyWithNonce<A, K> = Pair<SymmetricKey<out A, NonceTrait.Required, out K>, ByteArray>
//first and second are deliberately swapped to avoid mixups
private typealias KeyWithNonceAuthenticating<A, K> = Pair<ByteArray, SymmetricKey<out A, NonceTrait.Required, out K>>


val KeyWithNonceAuthenticating<*, *>.nonce: ByteArray @JvmName("nonceAuthenticating") get() = first
val KeyWithNonce<*, *>.nonce: ByteArray get() = second