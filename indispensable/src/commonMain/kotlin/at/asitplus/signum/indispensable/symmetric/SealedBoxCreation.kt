package at.asitplus.signum.indispensable.symmetric

import at.asitplus.catching
import kotlin.jvm.JvmName


/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] it was created for.
 * Use this function to load external encrypted data for decryption.
 *
 * Returns a KmmResult purely for the sake of consistency
 */
@JvmName("sealedBoxUnauthedWithNonce")
fun SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>.sealedBoxFrom(
    nonce: ByteArray,
    encryptedData: ByteArray
) = catching {
    SealedBox.WithNonce.Unauthenticated(
        nonce,
        Ciphertext.Unauthenticated(
            this,
            encryptedData
        )
    )
}

/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] it was created for.
 * Use this function to load external encrypted data for decryption.
 * Returns a KmmResult purely for the sake of consistency
 */
fun SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>.sealedBoxFrom(
    encryptedData: ByteArray
) = catching {
    SealedBox.WithoutNonce.Unauthenticated(
        Ciphertext.Unauthenticated(
            this,
            encryptedData
        )
    )
}


/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] it was created for.
 * Use this function to load external encrypted data for decryption.
 *
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("sealedBoxAuthenticatedWith")
fun SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Required, *>.sealedBoxFrom(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = catching {
    require(authTag.size == this.authCapability.tagLength.bytes.toInt()) { "Illegal auth tag length! expected: ${authTag.size * 8}, actual: ${this.authCapability.tagLength.bits}" }
    when (isIntegrated()) {
        false -> SealedBox.WithNonce.Authenticated<KeyType.WithDedicatedMacKey>(
            nonce,
            authenticatedCipherText(encryptedData, authTag, authenticatedData)
        )

        true -> SealedBox.WithNonce.Authenticated<KeyType.Integrated>(
            nonce,
            authenticatedCipherText(encryptedData, authTag, authenticatedData)
        )
    }
}

/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] it was created for.
 * Use this function to load external encrypted data for decryption.
 *
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("sealedBoxAuthenticatedWithout")
fun SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Without, *>.sealedBoxFrom(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = catching {
    require(authTag.size == this.authCapability.tagLength.bytes.toInt()) { "Illegal auth tag length! expected: ${authTag.size * 8}, actual: ${this.authCapability.tagLength.bits}" }
    when (hasDedicatedMac()) {
        true -> SealedBox.WithoutNonce.Authenticated<KeyType.WithDedicatedMacKey>(
            authenticatedCipherText(encryptedData, authTag, authenticatedData)
        )

        false -> SealedBox.WithoutNonce.Authenticated<KeyType.Integrated>(
            @Suppress("UNCHECKED_CAST")
            (this as SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, NonceTrait.Without, KeyType.Integrated>).authenticatedCipherText(
                encryptedData,
                authTag,
                authenticatedData
            )
        )
    }
}

private inline fun <reified A : AuthCapability.Authenticated<K>, reified I : NonceTrait, K : KeyType> SymmetricEncryptionAlgorithm<A, I, K>.authenticatedCipherText(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = Ciphertext.Authenticated<A, I, SymmetricEncryptionAlgorithm<A, I, K>, K>(
    this,
    encryptedData,
    authTag,
    authenticatedData
)