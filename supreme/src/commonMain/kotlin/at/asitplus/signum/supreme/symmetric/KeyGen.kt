package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.encoding.bitLength
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.symmetric.*
import org.kotlincrypto.SecureRandom
import kotlin.jvm.JvmName

private val secureRandom = SecureRandom()

/**
 * Generates a fresh random key for this algorithm.
 */
fun <A : AuthCapability<out K>, I : WithNonce, K : KeyType> SymmetricEncryptionAlgorithm<A, I, K>.randomKey(): SymmetricKey<A, I, out K> =
    keyFromInternal(
        secureRandom.nextBytesOf(keySize.bytes.toInt()),
        if (authCapability.keyType is KeyType.WithDedicatedMacKey) secureRandom.nextBytesOf(keySize.bytes.toInt())
        else null
    ) as SymmetricKey<A, I, out K>

/**
 * Generates a fresh random key for this algorithm.
 * [macKeyLength] can be specified to override [AuthCapability.Authenticated.WithDedicatedMac.preferredMacKeyLength].
 */
@JvmName("randomKeyAndMacKey")
fun <I : WithNonce> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>.randomKey(
    macKeyLength: BitLength = authCapability.preferredMacKeyLength
): SymmetricKey.WithDedicatedMac<I> =
    keyFromInternal(
        secureRandom.nextBytesOf(keySize.bytes.toInt()),
        secureRandom.nextBytesOf(macKeyLength.bytes.toInt())
    ) as SymmetricKey.WithDedicatedMac<I>

/**
 * Generates a new random nonce matching the Nonce size of this algorithm.
 * You typically don't want to use this, but have your nonces auto-generated during the encryption process
 */
@HazardousMaterials("Don't explicitly generate nonces!")
fun SymmetricEncryptionAlgorithm<*, WithNonce.Yes, *>.randomNonce(): ByteArray =
    secureRandom.nextBytesOf((withNonce.length.bytes).toInt())


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
            true -> when (this.isIntegrated()) {

                false -> {this
                    SymmetricKey.WithDedicatedMac.RequiringNonce(this, bytes, dedicatedMacKey!!)
                }
                true -> SymmetricKey.Integrated.Authenticating.RequiringNonce(this, bytes)
            }

            false -> SymmetricKey.Integrated.NonAuthenticating.RequiringNonce(this, bytes)
        }

        false -> when (isAuthenticated()) {
            true -> when (this.isIntegrated()) {
                false -> SymmetricKey.WithDedicatedMac.WithoutNonce(this, bytes, dedicatedMacKey!!)
                true -> SymmetricKey.Integrated.Authenticating.WithoutNonce(this, bytes)
            }

            false -> SymmetricKey.Integrated.NonAuthenticating.WithoutNonce(this, bytes)
        }
    }
}

/**
 * Creates a [SymmetricKey] from the specified [bytes].
 * Returns [KmmResult.failure] in case the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize]
 */
@JvmName("fixedKeyIntegrated")
fun <I : WithNonce> SymmetricEncryptionAlgorithm<AuthCapability<KeyType.Integrated>, I, KeyType.Integrated>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AuthCapability<KeyType.Integrated>, I, KeyType.Integrated>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(
            bytes,
            null
        )
    } as KmmResult<SymmetricKey<AuthCapability<KeyType.Integrated>, I, KeyType.Integrated>>


/**
 * Creates a [SymmetricKey] from the specified [bytes].
 * Returns [KmmResult.failure] in case the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize]
 */
@JvmName("fixedKeyAuthenticatedIntegrated")
fun <I : WithNonce> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<KeyType.Integrated>, I, KeyType.Integrated>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(
            bytes,
            null
        )
    } as KmmResult<SymmetricKey<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>>

/**
 * Creates a [SymmetricKey] from the specified [bytes].
 * Returns [KmmResult.failure] in case the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize] or the specified [macKey] is empty.
 */
@JvmName("fixedKeyDedicatedMacKey")
fun <I : WithNonce> SymmetricEncryptionAlgorithm<AuthCapability<KeyType.WithDedicatedMacKey>, I, KeyType.WithDedicatedMacKey>.keyFrom(
    encryptionKey: ByteArray,
    macKey: ByteArray
): KmmResult<SymmetricKey<AuthCapability<KeyType.WithDedicatedMacKey>, I, KeyType.WithDedicatedMacKey>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(
            encryptionKey,
            macKey
        )
    } as KmmResult<SymmetricKey<AuthCapability<KeyType.WithDedicatedMacKey>, I, KeyType.WithDedicatedMacKey>>
