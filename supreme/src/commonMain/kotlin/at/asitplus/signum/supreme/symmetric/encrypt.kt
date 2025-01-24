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
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 * This is the method you want to use, as it generates a fresh IV, if the underlying cipher requires an IV.
 * * [authenticatedData] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [authenticatedData], as both IV and AAD will be added to any [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@JvmName("encryptAuthenticated")
fun <A : CipherKind.Authenticated, I : Nonce> SymmetricKey<A, I>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        authenticatedData,
    ).encrypt(data) as SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
}
