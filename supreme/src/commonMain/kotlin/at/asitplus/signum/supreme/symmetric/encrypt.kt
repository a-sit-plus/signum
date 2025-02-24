package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.symmetric.*
import kotlin.jvm.JvmName

/**
 * Encrypts [data] and automagically generates a fresh nonce/IV if required by the cipher.
 *
 * @return [KmmResult.success] containing a [SealedBox] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., algorithm mismatch, key length, …)
 */
@JvmName("encryptWithAutoGenIV")
suspend fun <K : KeyType, A : AuthCapability<out K>, I : NonceTrait> SymmetricKey<A, I, out K>.encrypt(
    data: ByteArray
): KmmResult<SealedBox<A, I, out K>> = catching {
    Encryptor(
        algorithm,
        if (this.hasDedicatedMacKey()) encryptionKey else secretKey,
        if (this.hasDedicatedMacKey()) macKey else null,
        aad = null
    ).encrypt(data)
}


/**
 * Encrypts [data] and automagically generates a fresh nonce/IV if required by the cipher.
 *
 * @param authenticatedData Additional data to be authenticated (i.e. fed into the auth tag generation) but not encrypted.
 * -
 * It is safe to discard the reference to this data, as the [SealedBox] resulting from this operation will carry the
 * corresponding type information. Hence, it is possible to simply access
 * [at.asitplus.signum.indispensable.symmetric.authenticatedData]
 *
 * @return [KmmResult.success] containing a [SealedBox] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., algorithm mismatch, key length, …)
 */
@JvmName("encryptAuthenticated")
suspend fun <K : KeyType, A : AuthCapability.Authenticated<out K>, I : NonceTrait> SymmetricKey<A, I, out K>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox<A, I, out K>> = catching {
    Encryptor(
        algorithm,
        if (this.hasDedicatedMacKey()) encryptionKey else secretKey,
        if (this.hasDedicatedMacKey()) macKey else null,
        aad = authenticatedData,
    ).encrypt(data)
}
