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
sealed interface SymmetricKey<A : AuthCapability<K>, I : NonceTrait, K : KeyType> {
    val algorithm: SymmetricEncryptionAlgorithm<A, I, K>

    /**
     * This is meant for storing additional properties, which may be relevant for certain use cases.
     * For example, Json Web Keys or Cose Keys may define an arbitrary key IDs.
     * This is not meant for Algorithm parameters! If an algorithm needs parameters, the implementing classes should be extended
     */
    //must be serializable, therefore <String,String>
    val additionalProperties: MutableMap<String, String>

    interface Authenticating<A : AuthCapability.Authenticated<K>, I : NonceTrait, K : KeyType> : SymmetricKey<A, I, K>
    interface NonAuthenticating<I : NonceTrait> : SymmetricKey<AuthCapability.Unauthenticated, I, KeyType.Integrated>

    interface RequiringNonce<A : AuthCapability<K>, K : KeyType> : SymmetricKey<A, NonceTrait.Required, K>
    interface WithoutNonce<A : AuthCapability<K>, K : KeyType> : SymmetricKey<A, NonceTrait.Without, K>

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    sealed class Integrated<A : AuthCapability<KeyType.Integrated>, I : NonceTrait>
    @HazardousMaterials("Does not check whether key size matched algorithm! Useful for testing, but not production!")

    constructor(
        override val algorithm: SymmetricEncryptionAlgorithm<A, I, KeyType.Integrated>,
        /**
         * The actual encryption key bytes
         */
        val secretKey: ByteArray
    ) :
        SymmetricKey<A, I, KeyType.Integrated> {
        sealed class Authenticating<I : NonceTrait>(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>,
            secretKey: ByteArray
        ) : Integrated<AuthCapability.Authenticated.Integrated, I>(algorithm, secretKey),
            SymmetricKey.Authenticating<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated> {

            class RequiringNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, NonceTrait.Required, KeyType.Integrated>,
                secretKey: ByteArray,
                override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
            ) : Authenticating<NonceTrait.Required>(
                algorithm, secretKey
            ), SymmetricKey.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>

            class WithoutNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, NonceTrait.Without, KeyType.Integrated>,
                secretKey: ByteArray,
                override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
            ) : Authenticating<NonceTrait.Without>(
                algorithm, secretKey
            ), SymmetricKey.WithoutNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>
        }

        sealed class NonAuthenticating<I : NonceTrait>(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I, KeyType.Integrated>,
            secretKey: ByteArray
        ) : Integrated<AuthCapability.Unauthenticated, I>(algorithm, secretKey), SymmetricKey.NonAuthenticating<I> {
            class RequiringNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>,
                secretKey: ByteArray,
                override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
            ) : NonAuthenticating<NonceTrait.Required>(algorithm, secretKey)

            class WithoutNonce(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>,
                secretKey: ByteArray,
                override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
            ) : NonAuthenticating<NonceTrait.Without>(algorithm, secretKey)
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
     */
    sealed class WithDedicatedMac<I : NonceTrait>
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
        val encryptionKey: ByteArray,
        /**
         * The actual dedicated MAX key bytes
         */
        val macKey: ByteArray
    ) : SymmetricKey<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>,
        SymmetricKey.Authenticating<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey> {
        class RequiringNonce(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, NonceTrait.Required>, NonceTrait.Required, KeyType.WithDedicatedMacKey>,
            secretKey: ByteArray,
            dedicatedMacKey: ByteArray,
            override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
        ) : WithDedicatedMac<NonceTrait.Required>(
            algorithm, secretKey, dedicatedMacKey
        ),
            SymmetricKey.RequiringNonce<AuthCapability.Authenticated.WithDedicatedMac<*, NonceTrait.Required>, KeyType.WithDedicatedMacKey>

        class WithoutNonce(
            algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, NonceTrait.Without>, NonceTrait.Without, KeyType.WithDedicatedMacKey>,
            secretKey: ByteArray,
            dedicatedMacKey: ByteArray,
            override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
        ) : WithDedicatedMac<NonceTrait.Without>(
            algorithm, secretKey, dedicatedMacKey
        ),
            SymmetricKey.WithoutNonce<AuthCapability.Authenticated.WithDedicatedMac<*, NonceTrait.Without>, KeyType.WithDedicatedMacKey>

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithDedicatedMac<*>) return false

            if (algorithm != other.algorithm) return false
            if (!encryptionKey.contentEquals(other.encryptionKey)) return false
            if (!macKey.contentEquals(other.macKey)) return false
            if (additionalProperties != other.additionalProperties) return false

            return true
        }

        override fun hashCode(): Int {
            var result = algorithm.hashCode()
            result = 31 * result + encryptionKey.contentHashCode()
            result = 31 * result + macKey.contentHashCode()
            return result
        }
    }
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<K>, K : KeyType, I : NonceTrait> SymmetricKey<A, I, K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricKey.Authenticating<A, I, K>)
        returns(false) implies (this@isAuthenticated is SymmetricKey.NonAuthenticating<I>)
    }
    return this.algorithm.authCapability is AuthCapability.Authenticated<*>
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability.Authenticated<*>, I : NonceTrait> SymmetricKey<A, I, *>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricKey.Integrated.Authenticating<I>)
        returns(false) implies (this@isIntegrated is SymmetricKey.WithDedicatedMac<I>)
    }
    return this.hasDedicatedMacKey()
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<*>, I : NonceTrait> SymmetricKey<A, I, *>.hasDedicatedMacKey(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMacKey is SymmetricKey.WithDedicatedMac<I>)
        returns(false) implies (this@hasDedicatedMacKey is SymmetricKey.Integrated<A, I>)
    }
    return this is SymmetricKey.WithDedicatedMac
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<K>, K : KeyType> SymmetricKey<A, *, K>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricKey.RequiringNonce<A, K>)
        returns(false) implies (this@requiresNonce is SymmetricKey.WithoutNonce<A, K>)
    }
    return algorithm.nonceTrait is NonceTrait.Required
}

/**
 * The actual encryption key bytes
 */
val <A : AuthCapability<out K>, I : NonceTrait, K : KeyType.Integrated> SymmetricKey<A, I, out K >.secretKey get() = (this as SymmetricKey.Integrated).secretKey
val <I : NonceTrait> SymmetricKey<AuthCapability.Authenticated.WithDedicatedMac<*,I>, I, out KeyType.WithDedicatedMacKey >.encryptionKey get() = (this as SymmetricKey.WithDedicatedMac).encryptionKey