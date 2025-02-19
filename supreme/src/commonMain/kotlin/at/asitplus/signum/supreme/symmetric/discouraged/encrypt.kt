package at.asitplus.signum.supreme.symmetric.discouraged

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
import at.asitplus.signum.supreme.symmetric.Encryptor
import kotlin.jvm.JvmName


/**
 * Encrypts [data] using the manually specified [nonce]. Check yourself, before you really, really wreck yourself!
 * * [nonce] =  _Initialization Vector_; **NEVER EVER RE-USE THIS!**
 * * [authenticatedData] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [nonce] and [authenticatedData], as both will be added to any  [SealedBox.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [SealedBox.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or nonce length)
 */
@HazardousMaterials("NEVER re-use a nonce/IV! Have them auto-generated instead!")
@JvmName("encryptAuthenticatedWithNonce")
fun <K : KeyType, A : AuthCapability.Authenticated<out K>> KeyWithNonceAuthenticating<A, out K>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox<A, NonceTrait.Required, out K>> = catching {
    Encryptor(
        second.algorithm,
        if (second.hasDedicatedMacKey()) (second as WithDedicatedMac<NonceTrait.Required>).encryptionKey else (second as SymmetricKey.Integrated<out A, NonceTrait.Required>).secretKey,
        if (second.hasDedicatedMacKey()) (second as WithDedicatedMac<NonceTrait.Required>).macKey else (second as SymmetricKey.Integrated<out A, NonceTrait.Required>).secretKey,
        first,
        authenticatedData,
    ).encrypt(data) as SealedBox<A, NonceTrait.Required,K>
}

/**
 * Encrypts [data] using the manually specified [nonce]. Check yourself, before you really, really wreck yourself!
 * * [nonce] =  _Initialization Vector_; **NEVER EVER RE-USE THIS!**
 *
 * It is safe to discard the reference to [nonce] and [authenticatedData], as both will be added to any  [SealedBox.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [SealedBox.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or nonce length)
 */
@HazardousMaterials("NEVER re-use a nonce/IV! Have them auto-generated instead!")
@JvmName("encryptWithNonce")
fun <K : KeyType, A : AuthCapability<out K>> KeyWithNonce<A, out K>.encrypt(
    data: ByteArray
): KmmResult<SealedBox.WithNonce<A, out K>> = catching {
    Encryptor(
        first.algorithm,
        if (first.hasDedicatedMacKey()) (first as WithDedicatedMac<NonceTrait.Required>).encryptionKey else (first as SymmetricKey.Integrated<out A, NonceTrait.Required>).secretKey,
        if (first.hasDedicatedMacKey()) (first as WithDedicatedMac<NonceTrait.Required>).macKey else null,
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
        require(nonce.size == algorithm.nonceTrait.length.bytes.toInt()) { "Nonce is empty!" }
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
        require(nonce.size == algorithm.nonceTrait.length.bytes.toInt()) { "Invalid nonce size!" }
        KeyWithNonceAuthenticating(nonce, this)
    }

private typealias KeyWithNonce<A, K> = Pair<SymmetricKey<out A, NonceTrait.Required, out K>, ByteArray>
//first and second are deliberately swapped to avoid mixups
private typealias KeyWithNonceAuthenticating<A, K> = Pair<ByteArray, SymmetricKey<out A, NonceTrait.Required, out K>>


val KeyWithNonceAuthenticating<*, *>.nonce: ByteArray @JvmName("nonceAuthenticating") get() = first
val KeyWithNonce<*, *>.nonce: ByteArray get() = second