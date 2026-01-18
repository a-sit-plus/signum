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
fun <E: SymmetricEncryptionAlgorithm.AuthenticatedRequiringNonce> SealedBoxBuilder.WithNonce.Having<E>.from(
    encryptedData: ByteArray,
    authTag: ByteArray
): KmmResult<SealedBox<E>> = catching {
    SealedBox.WithNonce(nonce, algorithm.authenticatedCipherText(encryptedData, authTag))
}


/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 * Returns a KmmResult purely for the sake of consistency, even though this operation will always success
 */
fun <E: SymmetricEncryptionAlgorithm.UnauthenticatedRequiringNonce> SealedBoxBuilder.WithNonce.Having<E>.from(
    encryptedData: ByteArray,
): KmmResult<SealedBox<E>> = catching {
    SealedBox.WithNonce(nonce, Ciphertext.Unauthenticated(algorithm, encryptedData))
}

/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 *
 * @return [at.asitplus.KmmResult.failure] on illegal auth tag length
 */
@JvmName("fromAuthenticatedWihtKeyType")
fun <E: SymmetricEncryptionAlgorithm.AuthenticatedWithoutNonce> SealedBoxBuilder.Without<E>.from(
    encryptedData: ByteArray,
    authTag: ByteArray
): KmmResult<SealedBox<E>> = catching {
    require(authTag.size.bytes == algorithm.authTagSize) { "Illegal auth tag length! expected: ${authTag.size * 8}, actual: ${algorithm.authTagSize.bits}" }
    SealedBox.WithoutNonce(algorithm.authenticatedCipherText(encryptedData, authTag))
}


/**
 * Creates a [SealedBox] matching the characteristics of the underlying [SealedBoxBuilder.algorithm].
 * Use this function to load external encrypted data for decryption.
 * Returns a KmmResult purely for the sake of consistency
 */
@JvmName("fromUnauthenticatedWithoutNonce")
fun <E: SymmetricEncryptionAlgorithm.UnauthenticatedWithoutNonce> SealedBoxBuilder.Without<E>.from(
    encryptedData: ByteArray,
): KmmResult<SealedBox<E>> = catching {
    SealedBox.WithoutNonce(Ciphertext.Unauthenticated(algorithm, encryptedData))
}

/**
 * [SealedBox] builder from [algorithm]
 */
sealed class SealedBoxBuilder<out E: SymmetricEncryptionAlgorithm<*, *>>(internal val algorithm: E) {
    sealed class WithNonce<out E: SymmetricEncryptionAlgorithm.RequiringNonce<*>>(algorithm: E) :
        SealedBoxBuilder<E>(algorithm) {
        class Awaiting<out E: SymmetricEncryptionAlgorithm.RequiringNonce<*>> internal constructor(algorithm: E) :
            WithNonce<E>(algorithm) {
            fun withNonce(nonce: ByteArray): Having<E> = Having(algorithm, nonce)
        }

        class Having<out E: SymmetricEncryptionAlgorithm.RequiringNonce<*>>(
            algorithm: E,
            internal val nonce: ByteArray
        ) : WithNonce<E>(algorithm)
    }

    class Without<out E: SymmetricEncryptionAlgorithm.WithoutNonce<*>>(algorithm: E) : SealedBoxBuilder<E>(algorithm)
}

/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10004;
 * * Authenticated encryption: &#10008;
 */
val <E: SymmetricEncryptionAlgorithm.UnauthenticatedRequiringNonce> E.sealedBox:
        SealedBoxBuilder.WithNonce.Awaiting<E>
    @JvmName("boxWithNonceUnauthenticated") get() = SealedBoxBuilder.WithNonce.Awaiting(this)


/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10008;
 */
val <E: SymmetricEncryptionAlgorithm.UnauthenticatedWithoutNonce> E.sealedBox:
        SealedBoxBuilder.Without<E>
    @JvmName("boxWithoutNonceUnauthenticated") get() = SealedBoxBuilder.Without(this)


/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10004;
 * * Authenticated encryption: &#10004;
 */
val <E: SymmetricEncryptionAlgorithm.RequiringNonce<*>> E.sealedBox:
        SealedBoxBuilder.WithNonce.Awaiting<E>
    @JvmName("boxWithNonceAuthenticated") get() = SealedBoxBuilder.WithNonce.Awaiting(this)


// we need both this one and the next two to work around https://youtrack.jetbrains.com/issue/KT-75444
/**
 * Creates a [SealedBoxBuilder] matching this algorithm's characteristics:
 * * Nonce requirement: &#10008;
 * * Authenticated encryption: &#10004;
 */
val <E: SymmetricEncryptionAlgorithm.AuthenticatedWithoutNonce> E.sealedBox:
        SealedBoxBuilder.Without<E>
    @JvmName("boxWithoutNonceAuthenticatedGeneric")  get() = SealedBoxBuilder.Without(this)

private fun <E: SymmetricEncryptionAlgorithm.Authenticated<*>> E.authenticatedCipherText(
    encryptedData: ByteArray,
    authTag: ByteArray,
) = Ciphertext.Authenticated(this, encryptedData, authTag)