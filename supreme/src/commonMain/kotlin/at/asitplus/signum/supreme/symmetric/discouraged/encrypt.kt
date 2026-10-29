package at.asitplus.signum.supreme.symmetric.discouraged

import at.asitplus.KmmResult
import at.asitplus.catching
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
 * @return [KmmResult.success] containing a [SealedBox.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or nonce length)
 */
@HazardousMaterials("NEVER re-use a nonce/IV! Have them auto-generated instead!")
@JvmName("encryptAuthenticatedWithNonce")
suspend fun <K : KeyType, A : AuthCapability.Authenticated<out K>> KeyWithNonceAuthenticating<A, out K>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox<A, NonceTrait.Required, out K>> = catching {
    val second = second
    @OptIn(SecretExposure::class) Encryptor(
        second.algorithm,
        if (second.hasDedicatedMacKey()) second.encryptionKey.getOrThrow() else second.secretKey.getOrThrow(),
        if (second.hasDedicatedMacKey()) second.macKey.getOrThrow() else second.secretKey.getOrThrow(),
        first,
        authenticatedData,
    ).encrypt(data) as SealedBox<A, NonceTrait.Required, K>
}

/**
 * Encrypts [data] using the manually specified [nonce]. Check yourself, before you really, really wreck yourself!
 * * [nonce] =  nonce/IV; **NEVER EVER RE-USE THIS!**
 *
 * It is safe to discard the reference to [nonce], as it will be added to any  [SealedBox.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [SealedBox.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or nonce length)
 */
@HazardousMaterials("NEVER re-use a nonce/IV! Have them auto-generated instead!")
@JvmName("encryptWithNonce")
suspend fun <K : KeyType, A : AuthCapability<out K>> KeyWithNonce<A, out K>.encrypt(
    data: ByteArray
): KmmResult<SealedBox.WithNonce<A, out K>> = catching {
    val first = first
    @OptIn(SecretExposure::class) Encryptor(
        first.algorithm,
        if (first.hasDedicatedMacKey()) first.encryptionKey.getOrThrow() else first.secretKey.getOrThrow(),
        if (first.hasDedicatedMacKey()) first.macKey.getOrThrow() else null,
        second,
        null,
    ).encrypt(data) as SealedBox.WithNonce<A, out K>
}

/**
 * This function can be used to feed a pre-set nonce into encryption functions.
 * This is usually not required, since all algorithms requiting a nonce/IV generate them by default
 * @see at.asitplus.signum.supreme.symmetric.randomNonce
 */
@HazardousMaterials("Nonce/IV re-use can have catastrophic consequences!")
fun <K : KeyType, A : AuthCapability<out K>> SymmetricKey<A, NonceTrait.Required, out K>.andPredefinedNonce(nonce: ByteArray) =
    catching {
        require(nonce.size == algorithm.nonceSize.bytes.toInt()) { "$algorithm requires a nonce of size ${algorithm.nonceSize}!" }
        KeyWithNonce(this, nonce)
    }

/**
 * This function can be used to feed a pre-set nonce into encryption functions.
 * This is usually not required, since all algorithms requiting a nonce/IV generate them by default
 * @see at.asitplus.signum.supreme.symmetric.randomNonce
 */
@HazardousMaterials("Nonce/IV re-use can have catastrophic consequences!")
@JvmName("authedKeyWithNonce")
fun <K : KeyType, A : AuthCapability.Authenticated<out K>> SymmetricKey<out A, NonceTrait.Required, out K>.andPredefinedNonce(
    nonce: ByteArray
) =
    catching {
        require(nonce.size == algorithm.nonceSize.bytes.toInt()) { "$algorithm requires a nonce of size ${algorithm.nonceSize}!" }
        KeyWithNonceAuthenticating(nonce, this)
    }

private typealias KeyWithNonce<A, K> = Pair<SymmetricKey<out A, NonceTrait.Required, out K>, ByteArray>
//first and second are deliberately swapped to avoid mixups
private typealias KeyWithNonceAuthenticating<A, K> = Pair<ByteArray, SymmetricKey<out A, NonceTrait.Required, out K>>


val KeyWithNonceAuthenticating<*, *>.nonce: ByteArray @JvmName("nonceAuthenticating") get() = first
val KeyWithNonce<*, *>.nonce: ByteArray get() = second