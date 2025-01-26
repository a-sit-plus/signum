package at.asitplus.signum.supreme.symmetric.discouraged

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
import at.asitplus.signum.supreme.symmetric.Encryptor
import kotlin.jvm.JvmName


/**
 * Encrypts [data] using a specified IV. Check yourself, before you really, really wreck yourself!
 * * [iv] =  _Initialization Vector_; **NEVER EVER RE-USE THIS!**
 * * [authenticatedData] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [iv] and [authenticatedData], as both will be added to any [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@HazardousMaterials
@JvmName("encryptAuthenticatedWithNonce")
fun <K : KeyType, A : AuthType.Authenticated<out K>> KeyWithNonceAuthenticating<A, out K>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox.WithNonce.Authenticated<K>> = catching {
    Encryptor(
        second.algorithm,
        second.secretKey,
        if (second is WithDedicatedMac) (second as WithDedicatedMac<Nonce.Required>).dedicatedMacKey else second.secretKey,
        first,
        authenticatedData,
    ).encrypt(data) as SealedBox.WithNonce.Authenticated<K>
}

@HazardousMaterials
@JvmName("encryptWithNonce")
fun <K : KeyType, A : AuthType<out K>> KeyWithNonce<A, out K>.encrypt(
    data: ByteArray
): KmmResult<SealedBox.WithNonce<A, out K>> = catching {
    Encryptor(
        first.algorithm,
        first.secretKey,
        if (first is WithDedicatedMac) (first as WithDedicatedMac<Nonce.Required>).dedicatedMacKey else first.secretKey,
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
fun <K : KeyType, A : AuthType<out K>> SymmetricKey<A, Nonce.Required, out K>.andPredefinedNonce(nonce: ByteArray) =
    catching {
        require(nonce.size == algorithm.nonce.length.bytes.toInt()) { "Nonce is empty!" }
        KeyWithNonce(this, nonce)
    }

/**
 * This function can be used to feed a pre-set nonce into encryption functions.
 * This is usually not required, since all algorithms requiting a nonce/IV generate them by default
 * @see at.asitplus.signum.supreme.symmetric.randomNonce
 */
@HazardousMaterials("Nonce/IV re-use can have catastrophic consequences!")
@JvmName("authedKeyWithNonce")
fun <K : KeyType, A : AuthType.Authenticated<out K>> SymmetricKey<out A, Nonce.Required, out K>.andPredefinedNonce(nonce: ByteArray) =
    catching {
        require(nonce.size == algorithm.nonce.length.bytes.toInt()) { "Invalid nonce size!" }
        KeyWithNonceAuthenticating(nonce, this)
    }

private typealias KeyWithNonce<A, K> = Pair<SymmetricKey<out A, Nonce.Required, out K>, ByteArray>
//types first and second are deliberately swapped
private typealias KeyWithNonceAuthenticating<A, K> = Pair<ByteArray, SymmetricKey<out A, Nonce.Required, out K>>
