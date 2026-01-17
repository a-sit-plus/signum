package at.asitplus.signum.indispensable.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.encoding.bitLength
import at.asitplus.signum.indispensable.misc.BitLength
import org.kotlincrypto.random.CryptoRand
import kotlin.jvm.JvmName

private inline fun randomBytes(n: Int, random: CryptoRand = CryptoRand.Default): ByteArray =
    ByteArray(n).also {   random.nextBytes(it)}

/**
 * Generates a fresh random key for this algorithm.
 */
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE", "UNCHECKED_CAST")
@kotlin.internal.LowPriorityInOverloadResolution
suspend fun <A : AuthCapability, I : NonceTrait> SymmetricEncryptionAlgorithm<A, I>.randomKey() =
    @OptIn(HazardousMaterials::class) randomKey(CryptoRand.Default)
/**
 * Generates a fresh random key for this algorithm.
 */
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE", "UNCHECKED_CAST")
@kotlin.internal.LowPriorityInOverloadResolution
@HazardousMaterials("The default randomness source is cryptographically secure. If you override it, make sure you know what you are doing (such as for deterministic tests).")
suspend fun <A : AuthCapability, I : NonceTrait> SymmetricEncryptionAlgorithm<A, I>.randomKey(
    random: CryptoRand
): SymmetricKey<A, I> =
    keyFromInternal(
        randomBytes(keySize.bytes.toInt(), random),
        if (hasDedicatedMac()) randomBytes(preferredMacKeyLength.bytes.toInt(), random)
        else null
    ) as SymmetricKey<A, I>



/**
 * Generates a fresh random key for this algorithm.
 * [macKeyLength] can be specified to override [preferredMacKeyLength].
 */
@JvmName("randomKeyAndMacKey")
@Suppress("UNCHECKED_CAST")
suspend fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac, I>.randomKey(
    macKeyLength: BitLength
) = @OptIn(HazardousMaterials::class) randomKey(macKeyLength, CryptoRand.Default)
/**
 * Generates a fresh random key for this algorithm.
 * [macKeyLength] can be specified to override [preferredMacKeyLength].
 */
@JvmName("randomKeyAndMacKey")
@Suppress("UNCHECKED_CAST")
@HazardousMaterials("The default randomness source is cryptographically secure. If you override it, make sure you know what you are doing (such as for deterministic tests).")
suspend fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac, I>.randomKey(
    macKeyLength: BitLength,
    random: CryptoRand
): SymmetricKey.WithDedicatedMac<I> =
    keyFromInternal(
        randomBytes(keySize.bytes.toInt(), random),
        randomBytes(macKeyLength.bytes.toInt(), random)
    ) as SymmetricKey.WithDedicatedMac<I>


/**
 * Generates a new random nonce matching the Nonce size of this algorithm.
 * You typically don't want to use this, but have your nonces auto-generated during the encryption process
 */
@HazardousMaterials("Don't explicitly generate nonces!")
fun SymmetricEncryptionAlgorithm<*, NonceTrait.Required>.randomNonce(): ByteArray =
    @OptIn(HazardousMaterials::class) randomNonce(CryptoRand.Default)

/**
 * Generates a new random nonce matching the Nonce size of this algorithm.
 * You typically don't want to use this, but have your nonces auto-generated during the encryption process
 */
@HazardousMaterials("Don't explicitly generate nonces!")
@HazardousMaterials("The default randomness source is cryptographically secure. If you override it, make sure you know what you are doing (such as for deterministic tests).")
fun SymmetricEncryptionAlgorithm<*, NonceTrait.Required>.randomNonce(random: CryptoRand): ByteArray =
    randomBytes((nonceSize.bytes).toInt(), random)


@OptIn(HazardousMaterials::class)
private fun SymmetricEncryptionAlgorithm<*, *>.keyFromInternal(
    bytes: ByteArray,
    dedicatedMacKey: ByteArray?
): SymmetricKey<*, *> {
    require(bytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${bytes.size * 8}. Required: keySize=${bytes.size.bitLength}" }
    dedicatedMacKey?.let {
        require(it.isNotEmpty()) { "Dedicated MAC key is empty!" }
    }
    @OptIn(HazardousMaterials::class)
    return when (this.requiresNonce()) {
        true -> when (isAuthenticated()) {
            true -> when (isIntegrated()) {
                false -> SymmetricKey.WithDedicatedMac.RequiringNonce(this, bytes, dedicatedMacKey!!)
                true -> SymmetricKey.Integrated.Authenticating.RequiringNonce(this, bytes)
            }

            false -> SymmetricKey.Integrated.NonAuthenticating.RequiringNonce(this, bytes)
        }

        false -> when (isAuthenticated()) {
            true -> when (isIntegrated()) {
                false -> SymmetricKey.WithDedicatedMac.WithoutNonce(this, bytes, dedicatedMacKey!!)
                true -> SymmetricKey.Integrated.Authenticating.WithoutNonce(this, bytes)
            }

            false -> SymmetricKey.Integrated.NonAuthenticating.WithoutNonce(this, bytes)
        }
    }
}

/**
 * Creates a [SymmetricKey] from the specified [secretKey].
 * Returns [KmmResult.failure] in case the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize]
 */
@JvmName("fixedKeyIntegrated")
@Suppress("UNCHECKED_CAST")
fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability.Integrated, I>.keyFrom(
    secretKey: ByteArray
): KmmResult<SymmetricKey<AuthCapability.Integrated, I>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *>).keyFromInternal(secretKey, null)
    } as KmmResult<SymmetricKey<AuthCapability.Integrated, I>>


/**
 * Creates a [SymmetricKey] from the specified [secretKey].
 * Returns [KmmResult.failure] in case the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize]
 */
@JvmName("fixedKeyAuthenticatedIntegrated")
@Suppress("UNCHECKED_CAST")
fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated, I>.keyFrom(
    secretKey: ByteArray
): KmmResult<SymmetricKey<AuthCapability.Authenticated.Integrated, I>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *>).keyFromInternal(secretKey, null)
    } as KmmResult<SymmetricKey<AuthCapability.Authenticated.Integrated, I>>

/**
 * Creates a [SymmetricKey] from the specified [encryptionKey] and [macKey].
 * Returns [KmmResult.failure] in case the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize] or the specified [macKey] is empty.
 */
@JvmName("fixedKeyDedicatedMacKey")
@Suppress("UNCHECKED_CAST")
fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac, I>.keyFrom(
    encryptionKey: ByteArray,
    macKey: ByteArray
): KmmResult<SymmetricKey<AuthCapability.Authenticated.WithDedicatedMac, I>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *>).keyFromInternal(encryptionKey, macKey)
    } as KmmResult<SymmetricKey<AuthCapability.Authenticated.WithDedicatedMac, I>>


suspend fun SpecializedSymmetricEncryptionAlgorithm.randomKey() =
    @OptIn(HazardousMaterials::class) randomKey(CryptoRand.Default)

@HazardousMaterials("The default randomness source is cryptographically secure. If you override it, make sure you know what you are doing (such as for deterministic tests).")
suspend fun SpecializedSymmetricEncryptionAlgorithm.randomKey(random: CryptoRand) =
    algorithm.randomKey(random)
