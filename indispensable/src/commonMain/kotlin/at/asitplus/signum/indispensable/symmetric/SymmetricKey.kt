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
sealed interface SymmetricKey<A : AuthCapability<K>, I : WithNonce, K : KeyType> {
    val algorithm: SymmetricEncryptionAlgorithm<A, I, K>
    /**
     * The actual encryption key bytes
     */
    val secretKey: ByteArray

    interface Authenticating<A : AuthCapability.Authenticated<K>, I : WithNonce, K : KeyType> : SymmetricKey<A, I, K>
    interface NonAuthenticating<I : WithNonce> : SymmetricKey<AuthCapability.Unauthenticated, I, KeyType.Integrated>

    interface RequiringNonce<A : AuthCapability<K>, K : KeyType> : SymmetricKey<A, WithNonce.Yes, K>
    interface WithoutNonce<A : AuthCapability<K>, K : KeyType> : SymmetricKey<A, WithNonce.No, K>

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    sealed class Integrated<A : AuthCapability<KeyType.Integrated>, I : WithNonce>
    @HazardousMaterials("Does not check whether key size matched algorithm! Useful for testing, but not production!")

    constructor(
        override val algorithm: SymmetricEncryptionAlgorithm<A, I, KeyType.Integrated>,
        override val secretKey: ByteArray
    ) :
        SymmetricKey<A, I, KeyType.Integrated> {
        sealed class Authenticating<I : WithNonce>(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>,
            secretKey: ByteArray
        ) : Integrated<AuthCapability.Authenticated.Integrated, I>(algorithm, secretKey),
            SymmetricKey.Authenticating<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated> {

            class RequiringNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, WithNonce.Yes, KeyType.Integrated>,
                secretKey: ByteArray
            ) : Authenticating<WithNonce.Yes>(
                algorithm, secretKey
            ), SymmetricKey.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>

            class WithoutNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, WithNonce.No, KeyType.Integrated>,
                secretKey: ByteArray
            ) : Authenticating<WithNonce.No>(
                algorithm, secretKey
            ), SymmetricKey.WithoutNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>
        }

        sealed class NonAuthenticating<I : WithNonce>(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I, KeyType.Integrated>,
            secretKey: ByteArray
        ) : Integrated<AuthCapability.Unauthenticated, I>(algorithm, secretKey), SymmetricKey.NonAuthenticating<I> {
            class RequiringNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, WithNonce.Yes, KeyType.Integrated>,
                secretKey: ByteArray
            ) : NonAuthenticating<WithNonce.Yes>(algorithm, secretKey)

            class WithoutNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, WithNonce.No, KeyType.Integrated>,
                secretKey: ByteArray
            ) : NonAuthenticating<WithNonce.No>(algorithm, secretKey)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Integrated<*, *>) return false

            if (algorithm != other.algorithm) return false
            if (!secretKey.contentEquals(other.secretKey)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = algorithm.hashCode()
            result = 31 * result + secretKey.contentHashCode()
            return result
        }
    }


    /**
     * Encryption key with dedicated MAC key. Used for non-authenticated ciphers that use an external MAC function to
     * bolt on AEAD capabilities, such as [SymmetricEncryptionAlgorithm.AES.GCM]
     * [dedicatedMacKey] defaults to [secretKey]
     */
    sealed class WithDedicatedMac<I : WithNonce>
    @HazardousMaterials("Does not check whether key size matched algorithm! Useful for testing, but not production!")
    /**
     * Do not invoke directly! use Supreme's `SymmetricEncryptionAlgorithm.randomKey()` and `SymmetricEncryptionAlgorithm.encryptionKeyFrom(bytes)`
     * This constructor does not check for matching key sizes to allow for testing error cases!
     */
    constructor(
        override val algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>,
        /**
         * The actual encryption key bytes
         */
        override val secretKey: ByteArray,
        /**
         * The actual dedicated MAX key bytes
         */
        val dedicatedMacKey: ByteArray
    ) : SymmetricKey<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>,
        SymmetricKey.Authenticating<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey> {
        class RequiringNonce(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, WithNonce.Yes>, WithNonce.Yes, KeyType.WithDedicatedMacKey>,
            secretKey: ByteArray,
            dedicatedMacKey: ByteArray
        ) : WithDedicatedMac<WithNonce.Yes>(
            algorithm, secretKey, dedicatedMacKey
        ),
            SymmetricKey.RequiringNonce<AuthCapability.Authenticated.WithDedicatedMac<*, WithNonce.Yes>, KeyType.WithDedicatedMacKey>

        class WithoutNonce(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, WithNonce.No>, WithNonce.No, KeyType.WithDedicatedMacKey>,
            secretKey: ByteArray,
            dedicatedMacKey: ByteArray
        ) : WithDedicatedMac<WithNonce.No>(
            algorithm, secretKey, dedicatedMacKey
        ),
            SymmetricKey.WithoutNonce<AuthCapability.Authenticated.WithDedicatedMac<*, WithNonce.No>, KeyType.WithDedicatedMacKey>

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithDedicatedMac<*>) return false

            if (algorithm != other.algorithm) return false
            if (!secretKey.contentEquals(other.secretKey)) return false
            if (!dedicatedMacKey.contentEquals(other.dedicatedMacKey)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = algorithm.hashCode()
            result = 31 * result + secretKey.contentHashCode()
            result = 31 * result + dedicatedMacKey.contentHashCode()
            return result
        }
    }
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<K>, K : KeyType, I : WithNonce> SymmetricKey<A, I, K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricKey.Authenticating<A, I, K>)
        returns(false) implies (this@isAuthenticated is SymmetricKey.NonAuthenticating<I>)
    }
    return this.algorithm.authCapability is AuthCapability.Authenticated<*>
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability.Authenticated<K>, K : KeyType, I : WithNonce> SymmetricKey<A, I, K>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricKey.Integrated.Authenticating<I>)
        returns(false) implies (this@isIntegrated is SymmetricKey.WithDedicatedMac<I>)
    }
    return this.algorithm.authCapability is AuthCapability.Authenticated.WithDedicatedMac<*,*>
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<K>, K : KeyType, I : WithNonce> SymmetricKey<A, I, K>.hasDedicatedMacKey(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMacKey is SymmetricKey.WithDedicatedMac<I>)
        returns(false) implies (this@hasDedicatedMacKey is SymmetricKey.Integrated<A, I>)
    }
    return this is SymmetricKey.WithDedicatedMac
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<K>, K : KeyType, I : WithNonce> SymmetricKey<A, I, K>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricKey.RequiringNonce<A, K>)
        returns(false) implies (this@requiresNonce is SymmetricKey.WithoutNonce<A, K>)
    }
    return algorithm.withNonce is WithNonce.Yes
}

