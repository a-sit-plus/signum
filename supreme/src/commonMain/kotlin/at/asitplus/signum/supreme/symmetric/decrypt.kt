package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.CipherKind.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
import at.asitplus.signum.supreme.mac.mac
import org.kotlincrypto.SecureRandom
import kotlin.jvm.JvmName


/**
 * Attempts to decrypt this ciphertext (which also holds IV, and in case of an authenticated ciphertext, AAD and auth tag) using the provided [key].
 * This is the function you typically want to use.
 */
fun <A : CipherKind> SealedBox<A, Nonce.Required, SymmetricEncryptionAlgorithm<A, Nonce.Required>>.decrypt(key: SymmetricKey<in A, Nonce.Required>): KmmResult<ByteArray> =
    catching {
        require(algorithm == key.algorithm) { "Somebody likes cursed casts!" }
        when (algorithm.cipher as CipherKind) {
            is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>>).decryptInternal(
                key.secretKey
            )

            is Authenticated.WithDedicatedMac<*, *> -> {
                key as SymmetricKey.WithDedicatedMac
                (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).decryptInternal(
                    key.secretKey, key.dedicatedMacKey
                )
            }

            is CipherKind.Unauthenticated -> (this as SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>).decryptInternal(
                key.secretKey
            )
        }
    }


@JvmName("decryptRawAuthenticated")
private fun SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

@JvmName("decryptRaw")
private fun SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

/**
 * Attempts to decrypt this ciphertext using the provided raw [secretKey].
 * If no [macKey] is provided, [secretKey] will be used as MAC key.
 * [dedicatedMacInputCalculation] can be used to override the [DefaultDedicatedMacInputCalculation] used to compute MAC input.
 */
private fun SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>.decryptInternal(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
): ByteArray {
    val iv: ByteArray? = if (this is SealedBox.WithNonce<*, *>) this@decryptInternal.nonce else null
    val aad = authenticatedData
    val authTag = authTag

    val algorithm = algorithm
    val innerCipher = algorithm.cipher.innerCipher
    val mac = algorithm.cipher.mac
    val dedicatedMacInputCalculation = algorithm.cipher.dedicatedMacInputCalculation
    val hmacInput = mac.dedicatedMacInputCalculation(encryptedData, iv, aad)

    if (!(mac.mac(macKey, hmacInput).getOrThrow().contentEquals(authTag)))
        throw IllegalArgumentException("Auth Tag mismatch!")

    val box: SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>> =
        (if (this is SealedBox.WithNonce<*, *>) (innerCipher as SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Required>).sealedBox(
            this.nonce,
            encryptedData
        ) else (innerCipher as SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Without>).sealedBox(
            encryptedData
        )) as SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>
    return box.doDecrypt(secretKey)
}