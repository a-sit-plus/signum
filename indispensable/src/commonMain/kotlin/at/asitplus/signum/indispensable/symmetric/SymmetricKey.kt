package at.asitplus.signum.indispensable.symmetric

import at.asitplus.KmmResult
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.SecretExposure
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

sealed interface KeyType {
    object Integrated : KeyType
    object WithDedicatedMacKey : KeyType
}

/**
 * Symmetric encryption key. Can only be used for the specified [algorithm].
 */
sealed interface SymmetricKey<A : AuthCapability<out K>, I : NonceTrait, K : KeyType> {
    val algorithm: SymmetricEncryptionAlgorithm<A, I, K>

    /**
     * This is meant for storing additional properties, which may be relevant for certain use cases.
     * For example, Json Web Keys or COSE keys may define an arbitrary key IDs.
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
    sealed interface Integrated<A : AuthCapability<KeyType.Integrated>, I : NonceTrait> :
        SymmetricKey<A, I, KeyType.Integrated> {


        override val algorithm: SymmetricEncryptionAlgorithm<A, I, KeyType.Integrated>

        /**
         * The actual encryption key bytes
         */
        @SecretExposure
        val secretKey: KmmResult<ByteArray>


        sealed class Authenticating<I : NonceTrait>(
            override val algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>,
            override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>(),
            secretKey: ByteArray
        ) : Integrated<AuthCapability.Authenticated.Integrated, I>,
            SymmetricKey.Authenticating<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated> {

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is Integrated<*, *>) return false

                if (algorithm != other.algorithm) return false
                @OptIn(SecretExposure::class)
                if (!secretKey.getOrNull().contentEquals(other.secretKey.getOrNull())) return false

                return true
            }

            override fun hashCode(): Int {
                var result = algorithm.hashCode()
                @OptIn(SecretExposure::class)
                result = 31 * result + secretKey.getOrNull().contentHashCode()
                return result
            }

            @SecretExposure
            override val secretKey = KmmResult.success(secretKey)

            class RequiringNonce internal constructor(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, NonceTrait.Required, KeyType.Integrated>,
                secretKey: ByteArray,
                additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
            ) : Authenticating<NonceTrait.Required>(
                algorithm, additionalProperties, secretKey
            ), SymmetricKey.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>

            class WithoutNonce internal constructor(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, NonceTrait.Without, KeyType.Integrated>,
                secretKey: ByteArray,
                additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
            ) : Authenticating<NonceTrait.Without>(
                algorithm, additionalProperties, secretKey
            ), SymmetricKey.WithoutNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>
        }

        sealed class NonAuthenticating<I : NonceTrait>(
            override val algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I, KeyType.Integrated>,
            override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>(),
            secretKey: ByteArray
        ) : Integrated<AuthCapability.Unauthenticated, I>,
            SymmetricKey.NonAuthenticating<I> {

            @SecretExposure
            override val secretKey = KmmResult.success(secretKey)

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is Integrated<*, *>) return false

                if (algorithm != other.algorithm) return false
                @OptIn(SecretExposure::class)
                if (!secretKey.getOrNull().contentEquals(other.secretKey.getOrNull())) return false

                return true
            }

            override fun hashCode(): Int {
                var result = algorithm.hashCode()
                @OptIn(SecretExposure::class)
                result = 31 * result + secretKey.getOrNull().contentHashCode()
                return result
            }


            class RequiringNonce internal constructor(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required, KeyType.Integrated>,
                secretKey: ByteArray,
                additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
            ) : NonAuthenticating<NonceTrait.Required>(algorithm, additionalProperties, secretKey)

            class WithoutNonce internal constructor(
                algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without, KeyType.Integrated>,
                secretKey: ByteArray,
                additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
            ) : NonAuthenticating<NonceTrait.Without>(algorithm, additionalProperties, secretKey)
        }


    }


    /**
     * Encryption key with dedicated MAC key. Used for non-authenticated ciphers that use an external MAC function to
     * bolt on AEAD capabilities, such as [SymmetricEncryptionAlgorithm.AES.GCM]
     */
    sealed interface WithDedicatedMac<I : NonceTrait>
        : SymmetricKey<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>,
        SymmetricKey.Authenticating<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey> {


        override val algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>

        /**
         * The actual encryption key bytes
         */
        @SecretExposure
        val encryptionKey: KmmResult<ByteArray>

        /**
         * The actual dedicated MAC key bytes
         */
        @SecretExposure
        val macKey: KmmResult<ByteArray>


        class RequiringNonce @HazardousMaterials("This constructor is public to enable testing. DO NOT USE IT!") constructor(
            override val algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, NonceTrait.Required>, NonceTrait.Required, KeyType.WithDedicatedMacKey>,
            encryptionKey: ByteArray,
            dedicatedMacKey: ByteArray,
            override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
        ) : WithDedicatedMac<NonceTrait.Required>,
            SymmetricKey.RequiringNonce<AuthCapability.Authenticated.WithDedicatedMac<*, NonceTrait.Required>, KeyType.WithDedicatedMacKey> {
            /**
             * The actual encryption key bytes
             *
             * This will fail for hardware-backed keys!
             */
            @SecretExposure
            override val encryptionKey: KmmResult<ByteArray> = KmmResult.success(encryptionKey)

            /**
             * The actual dedicated MAC key bytes
             *
             * This will fail for hardware-backed keys!
             */
            @SecretExposure
            override val macKey: KmmResult<ByteArray> = KmmResult.success(dedicatedMacKey)

            @OptIn(SecretExposure::class)
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is WithDedicatedMac<*>) return false

                if (algorithm != other.algorithm) return false
                if (!encryptionKey.getOrNull().contentEquals(other.encryptionKey.getOrNull())) return false
                if (!macKey.getOrNull().contentEquals(other.macKey.getOrNull())) return false
                if (additionalProperties != other.additionalProperties) return false

                return true
            }

            @OptIn(SecretExposure::class)
            override fun hashCode(): Int {
                var result = algorithm.hashCode()
                result = 31 * result + encryptionKey.getOrNull().contentHashCode()
                result = 31 * result + macKey.getOrNull().contentHashCode()
                return result
            }


        }

        class WithoutNonce internal constructor(
            override val algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, NonceTrait.Without>, NonceTrait.Without, KeyType.WithDedicatedMacKey>,
            encryptionKey: ByteArray,
            dedicatedMacKey: ByteArray,
            override val additionalProperties: MutableMap<String, String> = mutableMapOf<String, String>()
        ) : WithDedicatedMac<NonceTrait.Without>,
            SymmetricKey.WithoutNonce<AuthCapability.Authenticated.WithDedicatedMac<*, NonceTrait.Without>, KeyType.WithDedicatedMacKey> {
            /**
             * The actual encryption key bytes
             *
             * This will fail for hardware-backed keys!
             */
            @SecretExposure
            override val encryptionKey: KmmResult<ByteArray> = KmmResult.success(encryptionKey)

            /**
             * The actual dedicated MAC key bytes
             *
             * This will fail for hardware-backed keys!
             */
            @SecretExposure
            override val macKey: KmmResult<ByteArray> = KmmResult.success(dedicatedMacKey)

            @OptIn(SecretExposure::class)
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is WithDedicatedMac<*>) return false

                if (algorithm != other.algorithm) return false
                if (!encryptionKey.getOrNull().contentEquals(other.encryptionKey.getOrNull())) return false
                if (!macKey.getOrNull().contentEquals(other.macKey.getOrNull())) return false
                if (additionalProperties != other.additionalProperties) return false

                return true
            }

            @OptIn(SecretExposure::class)
            override fun hashCode(): Int {
                var result = algorithm.hashCode()
                result = 31 * result + encryptionKey.getOrNull().contentHashCode()
                result = 31 * result + macKey.getOrNull().contentHashCode()
                return result
            }
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
 *
 * This will fail for hardware-backed keys!
 */
@SecretExposure
val <A : AuthCapability<out KeyType.Integrated>, I : NonceTrait> SymmetricKey<A, I, out KeyType.Integrated>.secretKey get() = (this as SymmetricKey.Integrated).secretKey

/**
 * The encryption key bytes, if present.
 *
 * This will fail for hardware-backed keys!
 */
@SecretExposure
val <A : AuthCapability.Authenticated.WithDedicatedMac<*, I>, I : NonceTrait> SymmetricKey<A, I, out KeyType.WithDedicatedMacKey>.encryptionKey get() = (this as SymmetricKey.WithDedicatedMac).encryptionKey

/**
 * The dedicated MAC key bytes, if present.
 *
 * This will fail for hardware-backed keys!
 */
@SecretExposure
val <A : AuthCapability.Authenticated.WithDedicatedMac<*, I>, I : NonceTrait> SymmetricKey<A, I, out KeyType.WithDedicatedMacKey>.macKey get() = (this as SymmetricKey.WithDedicatedMac).macKey
