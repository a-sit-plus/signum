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
fun <A : AuthCapability.Authenticated> SealedBoxBuilder.WithNonce.Having<A>.from(
    encryptedData: ByteArray,
    authTag: ByteArray
): KmmResult<SealedBox<A, NonceTrait.Required>> = catching {
    @Suppress("UNCHECKED_CAST")
    SealedBox.WithNonce.Authenticated(
        nonce,
        algorithm.authenticatedCipherText(encryptedData, authTag)
    ) as SealedBox<A, NonceTrait.Required>  //TODO why is this an unchecked cast???
}


/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 * Returns a KmmResult purely for the sake of consistency, even though this operation will always success
 */
fun SealedBoxBuilder.WithNonce.Having<AuthCapability.Unauthenticated>.from(
    encryptedData: ByteArray,
): KmmResult<SealedBox<AuthCapability.Unauthenticated, NonceTrait.Required>> = catching {
    SealedBox.WithNonce.Unauthenticated(
        nonce,
        Ciphertext.Unauthenticated(algorithm, encryptedData)
    )
}

/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 *
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("fromAuthenticatedWihtKeyType")
fun SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated>.from(
    encryptedData: ByteArray,
    authTag: ByteArray
): KmmResult<SealedBox<AuthCapability.Authenticated, NonceTrait.Without>> = catching {
    require(authTag.size.bytes == algorithm.authTagSize) { "Illegal auth tag length! expected: ${authTag.size * 8}, actual: ${algorithm.authTagSize.bits}" }
    SealedBox.WithoutNonce.Authenticated(
        algorithm.authenticatedCipherText(encryptedData, authTag)
    )
}


/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 * Returns a KmmResult purely for the sake of consistency
 */
@JvmName("fromUnauthenticatedWithoutNonce")
fun SealedBoxBuilder.Without<AuthCapability.Unauthenticated>.from(
    encryptedData: ByteArray,
): KmmResult<SealedBox<AuthCapability.Unauthenticated, NonceTrait.Without>> = catching {
    SealedBox.WithoutNonce.Unauthenticated(
        Ciphertext.Unauthenticated(algorithm, encryptedData)
    )
}

/**
 * [SealedBox] builder from [algorithm]
 */
sealed class SealedBoxBuilder<A : AuthCapability, I : NonceTrait>(internal val algorithm: SymmetricEncryptionAlgorithm<A, I>) {
    sealed class WithNonce<A : AuthCapability>(algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required>) :
        SealedBoxBuilder<A, NonceTrait.Required>(algorithm) {
        class Awaiting<A : AuthCapability> internal constructor(algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required>) :
            WithNonce<A>(algorithm) {
            @Suppress("UNCHECKED_CAST")
            fun withNonce(nonce: ByteArray): Having<A> = when (algorithm.isAuthenticated()) {
                true -> Having.Authenticated(
                    algorithm as SymmetricEncryptionAlgorithm<AuthCapability.Authenticated, NonceTrait.Required>,
                    nonce
                )

                false -> Having.Unauthenticated(
                    algorithm as SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required>,
                    nonce
                )
            } as Having<A>

        }

        sealed class Having<A : AuthCapability>(
            algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required>,
            internal val nonce: ByteArray
        ) : WithNonce<A>(algorithm) {
            class Authenticated<A : AuthCapability.Authenticated> internal constructor(
                algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required>,
                nonce: ByteArray,
            ) : Having<A>(algorithm, nonce)

            class Unauthenticated internal constructor(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required>,
                nonce: ByteArray
            ) : Having<AuthCapability.Unauthenticated>(algorithm, nonce)
        }
    }

    sealed class Without<A : AuthCapability>(algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Without>) :
        SealedBoxBuilder<A, NonceTrait.Without>(algorithm) {
        class Authenticated<A : AuthCapability.Authenticated> internal constructor(
            algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Without>,
        ) : Without<A>(algorithm)

        class Unauthenticated internal constructor(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without>,
        ) : Without<AuthCapability.Unauthenticated>(algorithm)
    }
}

/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10004;
 * * Authenticated encryption: &#10008;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required>.sealedBox:
        SealedBoxBuilder.WithNonce.Awaiting<AuthCapability.Unauthenticated>
    @JvmName("boxWithNonceUnauthenticated") get() = SealedBoxBuilder.WithNonce.Awaiting<AuthCapability.Unauthenticated>(
        this
    )


/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10008;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without>.sealedBox:
        SealedBoxBuilder.Without<AuthCapability.Unauthenticated>
    @JvmName("boxWithoutNonceUnauthenticated") get() = SealedBoxBuilder.Without.Unauthenticated(this)


/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10004;
 * * Authenticated encryption: &#10004;
 */
val <A : AuthCapability.Authenticated> SymmetricEncryptionAlgorithm<A, NonceTrait.Required>.sealedBox:
        SealedBoxBuilder.WithNonce.Awaiting<A>
    @JvmName("boxWithNonceAuthenticated") get() = SealedBoxBuilder.WithNonce.Awaiting(this)


// we need both this one and the next two to work around https://youtrack.jetbrains.com/issue/KT-75444
/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10004;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated, NonceTrait.Without>.sealedBox:
        SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated>
    @JvmName("boxWithoutNonceAuthenticatedGeneric")  get() = SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated>(this)

/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10004;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, NonceTrait.Without>.sealedBox:
        SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated.Integrated>
    @JvmName("boxWithoutNonceAuthenticatedIntegrated")  get() = SealedBoxBuilder.Without.Authenticated(
        this
    )

/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10004;
 */
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac, NonceTrait.Without>.sealedBox:
        SealedBoxBuilder.Without.Authenticated<AuthCapability.Authenticated.WithDedicatedMac>
    @JvmName("boxWithoutNonceAuthenticatedDedicated") get() = SealedBoxBuilder.Without.Authenticated(
        this
    )


private inline fun <reified A : AuthCapability.Authenticated, reified I : NonceTrait> SymmetricEncryptionAlgorithm<A, I>.authenticatedCipherText(
    encryptedData: ByteArray,
    authTag: ByteArray,
) = Ciphertext.Authenticated<A, I, SymmetricEncryptionAlgorithm<A, I>>(
    this,
    encryptedData,
    authTag,
)