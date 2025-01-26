package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

sealed interface KeyType {
    object Integrated : KeyType
    object WithDedicatedMacKey : KeyType
}

/**
 * Symmetric encryption key. Can only be used for the specified [algorithm].
 */
sealed interface SymmetricKey<A : AuthType<K>, I : Nonce, K : KeyType> {
    val algorithm: SymmetricEncryptionAlgorithm<A, I, K>
    val secretKey: ByteArray

    interface Authenticating<A : AuthType.Authenticated<K>, I : Nonce, K : KeyType> : SymmetricKey<A, I, K>
    interface NonAuthenticating<I : Nonce> : SymmetricKey<AuthType.Unauthenticated, I, KeyType.Integrated>

    interface RequiringNonce<A : AuthType<K>, K : KeyType> : SymmetricKey<A, Nonce.Required, K>
    interface WithoutNonce<A : AuthType<K>, K : KeyType> : SymmetricKey<A, Nonce.Without, K>

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    sealed class Integrated<A : AuthType<KeyType.Integrated>, I : Nonce>
    @HazardousMaterials("Does not check whether key size matched algorithm! Useful for testing, but not production!")
    /**
     * Do not invoke directly! use Supreme's `SymmetricEncryptionAlgorithm.randomKey()` and `SymmetricEncryptionAlgorithm.encryptionKeyFrom(bytes)`
     * This constructor does not check for matching key sizes to allow for testing error cases!
     */
    constructor(
        override val algorithm: SymmetricEncryptionAlgorithm<A, I, KeyType.Integrated>,
        override val secretKey: ByteArray
    ) :
        SymmetricKey<A, I, KeyType.Integrated> {
        sealed class Authenticating<I : Nonce>(
            algorithm: SymmetricEncryptionAlgorithm<AuthType.Authenticated.Integrated, I, KeyType.Integrated>,
            secretKey: ByteArray
        ) : Integrated<AuthType.Authenticated.Integrated, I>(algorithm, secretKey),
            SymmetricKey.Authenticating<AuthType.Authenticated.Integrated, I, KeyType.Integrated> {

            class RequiringNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthType.Authenticated.Integrated, Nonce.Required, KeyType.Integrated>,
                secretKey: ByteArray
            ) : Authenticating<Nonce.Required>(
                algorithm, secretKey
            ), SymmetricKey.RequiringNonce<AuthType.Authenticated.Integrated, KeyType.Integrated>

            class WithoutNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthType.Authenticated.Integrated, Nonce.Without, KeyType.Integrated>,
                secretKey: ByteArray
            ) : Authenticating<Nonce.Without>(
                algorithm, secretKey
            ), SymmetricKey.WithoutNonce<AuthType.Authenticated.Integrated, KeyType.Integrated>
        }

        sealed class NonAuthenticating<I : Nonce>(
            algorithm: SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, I, KeyType.Integrated>,
            secretKey: ByteArray
        ) : Integrated<AuthType.Unauthenticated, I>(algorithm, secretKey), SymmetricKey.NonAuthenticating<I> {
            class RequiringNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, Nonce.Required, KeyType.Integrated>,
                secretKey: ByteArray
            ) : NonAuthenticating<Nonce.Required>(algorithm, secretKey)

            class WithoutNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, Nonce.Without, KeyType.Integrated>,
                secretKey: ByteArray
            ) : NonAuthenticating<Nonce.Without>(algorithm, secretKey)
        }
    }


    /**
     * Encryption key with dedicated MAC key. Used for non-authenticated ciphers that use an external MAC function to
     * bolt-on AEAD capabilities, such as [SymmetricEncryptionAlgorithm.AES.GCM]
     * [dedicatedMacKey] defaults to [secretKey]
     */
    sealed class WithDedicatedMac<I : Nonce>
    @HazardousMaterials("Does not check whether key size matched algorithm! Useful for testing, but not production!")
    /**
     * Do not invoke directly! use Supreme's `SymmetricEncryptionAlgorithm.randomKey()` and `SymmetricEncryptionAlgorithm.encryptionKeyFrom(bytes)`
     * This constructor does not check for matching key sizes to allow for testing error cases!
     */
    constructor(
        override val algorithm: SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>,
        override val secretKey: ByteArray,
        val dedicatedMacKey: ByteArray
    ) : SymmetricKey<AuthType.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>,
        SymmetricKey.Authenticating<AuthType.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey> {
        class RequiringNonce(
            algorithm: SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required, KeyType.WithDedicatedMacKey>,
            secretKey: ByteArray,
            dedicatedMacKey: ByteArray
        ) : WithDedicatedMac<Nonce.Required>(
            algorithm, secretKey, dedicatedMacKey
        ),
            SymmetricKey.RequiringNonce<AuthType.Authenticated.WithDedicatedMac<*, Nonce.Required>, KeyType.WithDedicatedMacKey>

        class WithoutNonce(
            algorithm: SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, Nonce.Without>, Nonce.Without, KeyType.WithDedicatedMacKey>,
            secretKey: ByteArray,
            dedicatedMacKey: ByteArray
        ) : WithDedicatedMac<Nonce.Without>(
            algorithm, secretKey, dedicatedMacKey
        ),
            SymmetricKey.WithoutNonce<AuthType.Authenticated.WithDedicatedMac<*, Nonce.Without>, KeyType.WithDedicatedMacKey>
    }
}

@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SymmetricKey<A, I, K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricKey.Authenticating<A, I, K>)
        returns(false) implies (this@isAuthenticated is SymmetricKey.NonAuthenticating<I>)
    }
    return this.algorithm.authCapability is AuthType.Authenticated<*>
}


@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SymmetricKey<A, I, K>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricKey.RequiringNonce<A, K>)
        returns(false) implies (this@requiresNonce is SymmetricKey.WithoutNonce<A, K>)
    }
    return algorithm.nonce is Nonce.Required
}

