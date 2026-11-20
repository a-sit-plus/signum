package at.asitplus.signum.indispensable.symmetric

import at.asitplus.KmmResult
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

/**
 * Symmetric encryption key. Can only be used for the specified [algorithm].
 */
sealed interface SymmetricKey<out E: SymmetricEncryptionAlgorithm<*, *>> {
    val algorithm: E

    /**
     * This is meant for storing additional properties, which may be relevant for certain use cases.
     * For example, Json Web Keys or COSE keys may define an arbitrary key IDs.
     * This is not meant for Algorithm parameters! If an algorithm needs parameters, the implementing classes should be extended
     */
    //must be serializable, therefore <String,String>
    val additionalProperties: MutableMap<String, String>

    typealias Authenticating<I> = SymmetricKey<SymmetricEncryptionAlgorithm.Authenticated<I>>
    typealias NonAuthenticating<I> = SymmetricKey<SymmetricEncryptionAlgorithm.Unauthenticated<I>>

    typealias RequiringNonce<A> = SymmetricKey<SymmetricEncryptionAlgorithm.RequiringNonce<A>>
    typealias WithoutNonce<A> = SymmetricKey<SymmetricEncryptionAlgorithm.WithoutNonce<A>>

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    typealias Integrated<I> = SymmetricKey<SymmetricEncryptionAlgorithm<AuthCapability.Integrated, I>>

    companion object {
        fun <E: SymmetricEncryptionAlgorithm.Integrated<*>> Integrated(
            algorithm: E,
            secretKey: ByteArray,
            additionalProperties: MutableMap<String, String> = mutableMapOf()
        ): SymmetricKey<E> = SymmetricKeyIntegrated(algorithm, secretKey, additionalProperties)

        @HazardousMaterials("This constructor is public to enable testing. DO NOT USE IT!")
        fun <E: SymmetricEncryptionAlgorithm.EncryptThenMAC<*>> WithDedicatedMac(
            algorithm: E,
            encryptionKey: ByteArray,
            dedicatedMacKey: ByteArray,
            additionalProperties: MutableMap<String, String> = mutableMapOf()
        ) : SymmetricKey<E> = SymmetricKeyWithDedicatedMac(
            algorithm,
            encryptionKey,
            dedicatedMacKey,
            additionalProperties
        )

    }


    /**
     * Encryption key with dedicated MAC key. Used for non-authenticated ciphers that use an external MAC function to
     * bolt on AEAD capabilities, such as [SymmetricEncryptionAlgorithm.AES.GCM]
     */
    typealias WithDedicatedMac<I> = SymmetricKey<SymmetricEncryptionAlgorithm.EncryptThenMAC<I>>
}

private class SymmetricKeyIntegrated<out E: SymmetricEncryptionAlgorithm.Integrated<*>>(
    override val algorithm: E,
    secretKey: ByteArray,
    override val additionalProperties: MutableMap<String, String> = mutableMapOf(),
) : SymmetricKey<E> {
    @SecretExposure
    val secretKey: KmmResult<ByteArray> = KmmResult.success(secretKey)
    @OptIn(SecretExposure::class)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SymmetricKeyIntegrated<*>) return false

        if (algorithm != other.algorithm) return false
        @OptIn(SecretExposure::class)
        if (!secretKey.getOrNull().contentEquals(other.secretKey.getOrNull())) return false

        return true
    }

    @OptIn(SecretExposure::class)
    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        @OptIn(SecretExposure::class)
        result = 31 * result + secretKey.getOrNull().contentHashCode()
        return result
    }
}

/**
 * The actual encryption key bytes
 */
@SecretExposure
val SymmetricKey.Integrated<*>.secretKey: KmmResult<ByteArray> get() = when(this) {
    is SymmetricKeyIntegrated -> secretKey
    is SymmetricKeyWithDedicatedMac<*> -> algorithm.absurd()
}

private class SymmetricKeyWithDedicatedMac<E: SymmetricEncryptionAlgorithm.EncryptThenMAC<*>> @HazardousMaterials("This constructor is public to enable testing. DO NOT USE IT!") constructor(
    override val algorithm: E,
    encryptionKey: ByteArray,
    dedicatedMacKey: ByteArray,
    override val additionalProperties: MutableMap<String, String> = mutableMapOf()
) : SymmetricKey<E> {
    /**
     * The actual encryption key bytes
     *
     * This will fail for hardware-backed keys!
     */
    @SecretExposure
    val encryptionKey: KmmResult<ByteArray> = KmmResult.success(encryptionKey)

    /**
     * The actual dedicated MAC key bytes
     *
     * This will fail for hardware-backed keys!
     */
    @SecretExposure
    val macKey: KmmResult<ByteArray> = KmmResult.success(dedicatedMacKey)

    @OptIn(SecretExposure::class)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SymmetricKeyWithDedicatedMac<*>) return false

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

@SecretExposure
val WithDedicatedMac<*>.encryptionKey: KmmResult<ByteArray> get() = when (this) {
    is SymmetricKeyWithDedicatedMac -> encryptionKey
    is SymmetricKeyIntegrated<*> -> algorithm.absurd()
}

@SecretExposure
val WithDedicatedMac<*>.macKey: KmmResult<ByteArray> get() = when (this) {
    is SymmetricKeyWithDedicatedMac -> macKey
    is SymmetricKeyIntegrated<*> -> algorithm.absurd()
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <I: NonceTrait<*>> SymmetricKey<SymmetricEncryptionAlgorithm<*, I>>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricKey.Authenticating<I>)
        returns(false) implies (this@isAuthenticated is SymmetricKey.NonAuthenticating<I>)
    }
    return algorithm.isAuthenticated()
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <I: NonceTrait<*>> SymmetricKey.Authenticating<I>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricKey.Integrated<I>)
        returns(false) implies (this@isIntegrated is WithDedicatedMac<I>)
    }
    return !this.hasDedicatedMacKey()
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <I: NonceTrait<*>> SymmetricKey<SymmetricEncryptionAlgorithm<*, I>>.hasDedicatedMacKey(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMacKey is WithDedicatedMac<I>)
        returns(false) implies (this@hasDedicatedMacKey is SymmetricKey.Integrated<I>)
    }
    return algorithm.hasDedicatedMac()
}

/**Use to smart cast*/
@OptIn(ExperimentalContracts::class)
fun <A: AuthCapability<*>> SymmetricKey<SymmetricEncryptionAlgorithm<A, *>>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricKey.RequiringNonce<A>)
        returns(false) implies (this@requiresNonce is SymmetricKey.WithoutNonce<A>)
    }
    return algorithm.requiresNonce()
}

interface SpecializedSymmetricKey {
    fun toSymmetricKey(): KmmResult<SymmetricKey<*>>
}
