package at.asitplus.signum.indispensable.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.misc.bytes
import kotlin.jvm.JvmName

/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 * Returns a KmmResult purely for the sake of consistency, even though this operation will always success
 */
fun <A : AuthCapability.Authenticated<out K>, K : KeyType> SealedBoxBuilder.WithNonce.Having<A, K>.from(
    encryptedData: ByteArray,
    authTag: ByteArray
): KmmResult<SealedBox<A, NonceTrait.Required, K>> = catching {
    @Suppress("UNCHECKED_CAST")
    SealedBox.WithNonce.Authenticated<K>(
        nonce,
        algorithm.authenticatedCipherText(encryptedData, authTag)
    ) as SealedBox<A, NonceTrait.Required, K>  //TODO why is this an unchecked cast???
}


/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 * Returns a KmmResult purely for the sake of consistency, even though this operation will always success
 */
fun SealedBoxBuilder.WithNonce.Having<AuthCapability.Unauthenticated, KeyType.Integrated>.from(
    encryptedData: ByteArray,
): KmmResult<SealedBox<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>> = catching {
    SealedBox.WithNonce.Unauthenticated(
        nonce,
        Ciphertext.Unauthenticated(algorithm, encryptedData)
    )
}

// we need both this one and the next to work around https://youtrack.jetbrains.com/issue/KT-75444
/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 *
 *
 *  @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("fromAuthenticatedGeneric")
fun SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated<*>, *>.from(
    encryptedData: ByteArray,
    authTag: ByteArray
): KmmResult<SealedBox<AuthCapability.Authenticated<*>, NonceTrait.Without, *>> = catching {
    require(authTag.size.bytes == algorithm.authTagSize) { "Illegal auth tag length! expected: ${authTag.size * 8}, actual: ${algorithm.authTagSize.bits}" }
    SealedBox.WithoutNonce.Authenticated<KeyType>(
        algorithm.authenticatedCipherText(encryptedData, authTag)
    )
}

/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 *
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("fromAuthenticatedWihtKeyType")
fun <K : KeyType> SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated<out K>, K>.from(
    encryptedData: ByteArray,
    authTag: ByteArray
): KmmResult<SealedBox<AuthCapability.Authenticated<out K>, NonceTrait.Without, K>> = catching {
    require(authTag.size.bytes == algorithm.authTagSize) { "Illegal auth tag length! expected: ${authTag.size * 8}, actual: ${algorithm.authTagSize.bits}" }
    SealedBox.WithoutNonce.Authenticated<K>(
        algorithm.authenticatedCipherText(encryptedData, authTag)
    )
}


/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 * Returns a KmmResult purely for the sake of consistency
 */
@JvmName("fromUnauthenticatedWithoutNonce")
fun SealedBoxBuilder.Without<AuthCapability.Unauthenticated, KeyType.Integrated>.from(
    encryptedData: ByteArray,
): KmmResult<SealedBox<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>> = catching {
    SealedBox.WithoutNonce.Unauthenticated(
        Ciphertext.Unauthenticated(algorithm, encryptedData)
    )
}

/**
 * [SealedBox] builder from [algorithm]
 */
sealed class SealedBoxBuilder<A : AuthCapability<out K>, I : NonceTrait, out K : KeyType>(internal val algorithm: SymmetricEncryptionAlgorithm<A, I, K>) {
    sealed class WithNonce<A : AuthCapability<out K>, K : KeyType>(algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K>) :
        SealedBoxBuilder<A, NonceTrait.Required, K>(algorithm) {
        class Awaiting<A : AuthCapability<out K>, K : KeyType> internal constructor(algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K>) :
            WithNonce<A, K>(algorithm) {
            @Suppress("UNCHECKED_CAST")
            fun withNonce(nonce: ByteArray): Having<A, K> = when (algorithm.isAuthenticated()) {
                true -> Having.Authenticated<AuthCapability.Authenticated<*>, KeyType>(
                    algorithm as SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Required, KeyType>,
                    nonce
                )

                false -> Having.Unauthenticated(
                    algorithm as SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>,
                    nonce
                )
            } as Having<A, K>

        }

        sealed class Having<A : AuthCapability<out K>, K : KeyType>(
            algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K>,
            internal val nonce: ByteArray
        ) : WithNonce<A, K>(algorithm) {
            class Authenticated<A : AuthCapability.Authenticated<out K>, K : KeyType> internal constructor(
                algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K>,
                nonce: ByteArray,
            ) : Having<A, K>(algorithm, nonce)

            class Unauthenticated internal constructor(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>,
                nonce: ByteArray
            ) : Having<AuthCapability.Unauthenticated, KeyType.Integrated>(algorithm, nonce)
        }
    }

    sealed class Without<A : AuthCapability<out K>, K : KeyType>(algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Without, K>) :
        SealedBoxBuilder<A, NonceTrait.Without, K>(algorithm) {
        class Authenticated<A : AuthCapability.Authenticated<out K>, K : KeyType> internal constructor(
            algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Without, K>,
        ) : Without<A, K>(algorithm)

        class Unauthenticated internal constructor(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>,
        ) : Without<AuthCapability.Unauthenticated, KeyType.Integrated>(algorithm)
    }
}

/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10004;
 * * Authenticated encryption: &#10008;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>.sealedBox:
        SealedBoxBuilder.WithNonce.Awaiting<AuthCapability.Unauthenticated, KeyType.Integrated>
    @JvmName("boxWithNonceUnauthenticated") get() = SealedBoxBuilder.WithNonce.Awaiting<AuthCapability.Unauthenticated, KeyType.Integrated>(
        this
    )


/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10008;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>.sealedBox:
        SealedBoxBuilder.Without<AuthCapability.Unauthenticated, KeyType.Integrated>
    @JvmName("boxWithoutNonceUnauthenticated") get() = SealedBoxBuilder.Without.Unauthenticated(this)


/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10004;
 * * Authenticated encryption: &#10004;
 */
val <K : KeyType, A : AuthCapability.Authenticated<out K>> SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K>.sealedBox:
        SealedBoxBuilder.WithNonce.Awaiting<A, K>
    @JvmName("boxWithNonceAuthenticated") get() = SealedBoxBuilder.WithNonce.Awaiting<A, K>(this)


// we need both this one and the next two to work around https://youtrack.jetbrains.com/issue/KT-75444
/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10004;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Without, *>.sealedBox:
        SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated<*>, *>
    @JvmName("boxWithoutNonceAuthenticatedGeneric")  get() = SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated<*>, KeyType>(this)

/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10004;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<KeyType.Integrated>, NonceTrait.Without, KeyType.Integrated>.sealedBox:
        SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated<KeyType.Integrated>, KeyType.Integrated>
    @JvmName("boxWithoutNonceAuthenticatedIntegrated")  get() = SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated<KeyType.Integrated>, KeyType.Integrated>(
        this
    )

/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10004;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<KeyType.WithDedicatedMacKey>, NonceTrait.Without, KeyType.WithDedicatedMacKey>.sealedBox:
        SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated<KeyType.WithDedicatedMacKey>, KeyType.WithDedicatedMacKey>
    @JvmName("boxWithoutNonceAuthenticatedDedicated") get() = SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated<KeyType.WithDedicatedMacKey>, KeyType.WithDedicatedMacKey>(
        this
    )


private inline fun <reified A : AuthCapability.Authenticated<out K>, reified I : NonceTrait, K : KeyType> SymmetricEncryptionAlgorithm<A, I, K>.authenticatedCipherText(
    encryptedData: ByteArray,
    authTag: ByteArray,
) = Ciphertext.Authenticated<A, I, SymmetricEncryptionAlgorithm<A, I, K>, K>(
    this,
    encryptedData,
    authTag,
)