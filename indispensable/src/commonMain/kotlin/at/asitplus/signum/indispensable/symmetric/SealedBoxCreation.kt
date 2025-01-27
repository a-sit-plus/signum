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
fun SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, Nonce.Required, KeyType.Integrated>.sealedBox(
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
fun SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, Nonce.Without, KeyType.Integrated>.sealedBox(
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
fun SymmetricEncryptionAlgorithm<AuthType.Authenticated<*>, Nonce.Required, *>.sealedBox(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = catching {
    require(authTag.size == this.authCapability.tagLen.bytes.toInt()) { "Illegal auth tag length! expected: ${authTag.size * 8}, actual: ${this.authCapability.tagLen.bits}" }
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
fun SymmetricEncryptionAlgorithm<AuthType.Authenticated<*>, Nonce.Without, *>.sealedBox(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = catching {
    require(authTag.size == this.authCapability.tagLen.bytes.toInt()) { "Illegal auth tag length! expected: ${authTag.size * 8}, actual: ${this.authCapability.tagLen.bits}" }
    when (hasDedicatedMac()) {
        true -> SealedBox.WithoutNonce.Authenticated<KeyType.WithDedicatedMacKey>(
            authenticatedCipherText(encryptedData, authTag, authenticatedData)
        )

        false -> SealedBox.WithoutNonce.Authenticated<KeyType.Integrated>(
            (this as SymmetricEncryptionAlgorithm<AuthType.Authenticated.Integrated, Nonce.Without, KeyType.Integrated>).authenticatedCipherText(
                encryptedData,
                authTag,
                authenticatedData
            )
        )
    }
}

private inline fun <reified A : AuthType.Authenticated<K>, reified I : Nonce, K : KeyType> SymmetricEncryptionAlgorithm<A, I, K>.authenticatedCipherText(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = Ciphertext.Authenticated<A, I, SymmetricEncryptionAlgorithm<A, I, K>, K>(
    this,
    encryptedData,
    authTag,
    authenticatedData
)