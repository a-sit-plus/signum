package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion
import at.asitplus.KmmResult.Companion.failure
import at.asitplus.KmmResult.Companion.success
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.CipherKind
import at.asitplus.signum.indispensable.symmetric.Nonce
import at.asitplus.signum.indispensable.symmetric.SealedBox
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
import kotlin.jvm.JvmName


@HazardousMaterials
@JvmName("encryptWithIV")
fun <A : CipherKind> SymmetricKey<A, Nonce.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray
): KmmResult<SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        iv,
        null,
    ).encrypt(data) as SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>
}

@JvmName("encryptWithAutoGenIV")
fun <A : CipherKind, I : Nonce> SymmetricKey<A, I>.encrypt(
    data: ByteArray
): KmmResult<SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        null,
    ).encrypt(data) as SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
}

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
fun <A : CipherKind.Authenticated> SymmetricKey<A, Nonce.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        iv,
        authenticatedData,
    ).encrypt(data) as SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>
}
