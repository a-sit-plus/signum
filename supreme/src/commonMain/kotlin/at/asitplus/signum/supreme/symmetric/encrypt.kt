package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
import kotlin.jvm.JvmName

/**
 * Encrypts [data] and automagically generates a fresh nonce/IV if required by the cipher.
 *
 * @return [KmmResult.success] containing a [SealedBox] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., algorithm mismatch, key length, …)
 */
@JvmName("encryptWithAutoGenIV")
fun <K: KeyType,A : AuthType<out K>, I : Nonce> SymmetricKey<A, I,out K>.encrypt(
    data: ByteArray
): KmmResult<SealedBox<A, I,out K>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        null,
    ).encrypt(data) as SealedBox<A, I,out  K>
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
fun <K: KeyType, A : AuthType.Authenticated<K>, I : Nonce> SymmetricKey<A, I,out K>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox<A, I,K>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        authenticatedData,
    ).encrypt(data) as SealedBox<A, I, K>
}
