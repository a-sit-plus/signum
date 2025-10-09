package at.asitplus.signum.indispensable.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.encoding.bitLength
import at.asitplus.signum.indispensable.misc.BitLength
import org.kotlincrypto.random.CryptoRand
import kotlin.jvm.JvmName
import kotlin.random.Random

private inline fun randomBytes(n: Int, randomnessSourceOverride: Random? = null) =
    randomnessSourceOverride?.nextBytes(n) ?: CryptoRand.Default.nextBytes(ByteArray(n))

/**
 * Generates a fresh random key for this algorithm.
 */
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE", "UNCHECKED_CAST")
@kotlin.internal.LowPriorityInOverloadResolution
suspend fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> SymmetricEncryptionAlgorithm<A, I, K>.randomKey(
    randomnessSourceOverride: Random? = null
): SymmetricKey<A, I, out K> =
    keyFromInternal(
        randomBytes(keySize.bytes.toInt(), randomnessSourceOverride),
        if (hasDedicatedMac()) randomBytes(preferredMacKeyLength.bytes.toInt())
        else null
    ) as SymmetricKey<A, I, out K>

/**
 * Generates a fresh random key for this algorithm.
 * [macKeyLength] can be specified to override [preferredMacKeyLength].
 */
@JvmName("randomKeyAndMacKey")
@Suppress("UNCHECKED_CAST")
suspend fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac, I, KeyType.WithDedicatedMacKey>.randomKey(
    macKeyLength: BitLength,
    randomnessSourceOverride: Random? = null
): SymmetricKey.WithDedicatedMac<I> =
    keyFromInternal(
        randomBytes(keySize.bytes.toInt(), randomnessSourceOverride),
        randomBytes(macKeyLength.bytes.toInt(), randomnessSourceOverride)
    ) as SymmetricKey.WithDedicatedMac<I>

/**
 * Generates a new random nonce matching the Nonce size of this algorithm.
 * You typically don't want to use this, but have your nonces auto-generated during the encryption process
 */
@HazardousMaterials("Don't explicitly generate nonces!")
fun SymmetricEncryptionAlgorithm<*, NonceTrait.Required, *>.randomNonce(randomnessSourceOverride: Random? = null): ByteArray =
    randomBytes((nonceSize.bytes).toInt(), randomnessSourceOverride)


@OptIn(HazardousMaterials::class)
private fun SymmetricEncryptionAlgorithm<*, *, *>.keyFromInternal(
    bytes: ByteArray,
    dedicatedMacKey: ByteArray?
): SymmetricKey<*, *, *> {
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
fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability<KeyType.Integrated>, I, KeyType.Integrated>.keyFrom(
    secretKey: ByteArray
): KmmResult<SymmetricKey<AuthCapability<KeyType.Integrated>, I, KeyType.Integrated>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(secretKey, null)
    } as KmmResult<SymmetricKey<AuthCapability<KeyType.Integrated>, I, KeyType.Integrated>>


/**
 * Creates a [SymmetricKey] from the specified [secretKey].
 * Returns [KmmResult.failure] in case the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize]
 */
@JvmName("fixedKeyAuthenticatedIntegrated")
@Suppress("UNCHECKED_CAST")
fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<KeyType.Integrated>, I, KeyType.Integrated>.keyFrom(
    secretKey: ByteArray
): KmmResult<SymmetricKey<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(secretKey, null)
    } as KmmResult<SymmetricKey<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>>

/**
 * Creates a [SymmetricKey] from the specified [encryptionKey] and [macKey].
 * Returns [KmmResult.failure] in case the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize] or the specified [macKey] is empty.
 */
@JvmName("fixedKeyDedicatedMacKey")
@Suppress("UNCHECKED_CAST")
fun <A : AuthCapability<KeyType.WithDedicatedMacKey>, I : NonceTrait> SymmetricEncryptionAlgorithm<A, I, KeyType.WithDedicatedMacKey>.keyFrom(
    encryptionKey: ByteArray,
    macKey: ByteArray
): KmmResult<SymmetricKey<A, I, KeyType.WithDedicatedMacKey>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(encryptionKey, macKey)
    } as KmmResult<SymmetricKey<A, I, KeyType.WithDedicatedMacKey>>

suspend fun SpecializedSymmetricEncryptionAlgorithm.randomKey(randomnessSourceOverride : Random? = null) =
    algorithm.randomKey(randomnessSourceOverride)
