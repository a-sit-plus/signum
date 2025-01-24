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
fun <A : AECapability.Authenticated> KeyWithNonceAuthenticating<A>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>> = catching {
    Encryptor(
        second.algorithm,
        second.secretKey,
        if (second is WithDedicatedMac) (second as WithDedicatedMac<Nonce.Required>).dedicatedMacKey else second.secretKey,
        first,
        authenticatedData,
    ).encrypt(data) as SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>
}

@HazardousMaterials
@JvmName("encryptWithNonce")
fun <A : AECapability> KeyWithNonce<A>.encrypt(
    data: ByteArray
): KmmResult<SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>> = catching {
    Encryptor(
        first.algorithm,
        first.secretKey,
        if (first is WithDedicatedMac) (first as WithDedicatedMac<Nonce.Required>).dedicatedMacKey else first.secretKey,
        second,
        null,
    ).encrypt(data) as SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>
}

/**
 * This function can be used to feed a pre-set nonce into encryption functions.
 * This is usually not required, since all algorithms requiting a nonce/IV generate them by default
 * @see at.asitplus.signum.supreme.symmetric.randomNonce
 */
@HazardousMaterials("Nonce/IV re-use can have catastrophic consequences!")
fun <A : AECapability> SymmetricKey<A, Nonce.Required>.andPredefinedNonce(nonce: ByteArray) = KeyWithNonce( this, nonce)

/**
 * This function can be used to feed a pre-set nonce into encryption functions.
 * This is usually not required, since all algorithms requiting a nonce/IV generate them by default
 * @see at.asitplus.signum.supreme.symmetric.randomNonce
 */
@HazardousMaterials("Nonce/IV re-use can have catastrophic consequences!")
@JvmName("authedKeyWithNonce")
fun <A : AECapability.Authenticated> SymmetricKey<A, Nonce.Required>.andPredefinedNonce(nonce: ByteArray) =
    KeyWithNonceAuthenticating(nonce, this)

private typealias KeyWithNonce<A> = Pair< SymmetricKey< A, Nonce.Required>, ByteArray>
//types first and second are deliberately swapped
private typealias KeyWithNonceAuthenticating<A> = Pair<ByteArray, SymmetricKey< A, Nonce.Required>>
