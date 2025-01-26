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


fun <A : AuthType<out K>, I : Nonce, K : KeyType> SymmetricEncryptionAlgorithm<A, I, K>.randomKey(): SymmetricKey<A, I, out K> =
    keyFromInternal(
        secureRandom.nextBytesOf(keySize.bytes.toInt()),
        if (authCapability.keyType is KeyType.WithDedicatedMacKey) secureRandom.nextBytesOf(keySize.bytes.toInt())
        else null
    ) as SymmetricKey<A, I, out K>


@JvmName("randomKeyAndMacKey")
fun <I : Nonce> SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>.randomKey(
    macKeyLength: BitLength = keySize
): SymmetricKey.WithDedicatedMac<I> =
    keyFromInternal(
        secureRandom.nextBytesOf(keySize.bytes.toInt()),
        secureRandom.nextBytesOf(macKeyLength.bytes.toInt())
    ) as SymmetricKey.WithDedicatedMac<I>

/**
 * Generates a new random Nonce matching the Nonce size of this algorithm.
 * You typically don't want to use this, but have your nonces auto-generated.
 */
@HazardousMaterials("Don't explicitly generate nonces!")
fun SymmetricEncryptionAlgorithm<*, Nonce.Required, *>.randomNonce(): ByteArray =
    secureRandom.nextBytesOf((nonce.length.bytes).toInt())


@OptIn(HazardousMaterials::class)
private fun SymmetricEncryptionAlgorithm<*, *, *>.keyFromInternal(
    bytes: ByteArray,
    dedicatedMacKey: ByteArray?
): SymmetricKey<*, *, *> {
    require(bytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${bytes.size * 8}. Required: keySize=${bytes.size.bitLength}" }
    @OptIn(HazardousMaterials::class)
    return when (this.requiresNonce()) {
        true -> when (isAuthenticated()) {
            true -> when (this.isIntegrated()) {
                false -> SymmetricKey.WithDedicatedMac.RequiringNonce(this, bytes, dedicatedMacKey!!)
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


@JvmName("fixedKeyIntegrated")
fun <I : Nonce> SymmetricEncryptionAlgorithm<AuthType<KeyType.Integrated>, I, KeyType.Integrated>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AuthType<KeyType.Integrated>, I, KeyType.Integrated>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(
            bytes,
            null
        )
    } as KmmResult<SymmetricKey<AuthType<KeyType.Integrated>, I, KeyType.Integrated>>



@JvmName("fixedKeyAuthenticatedIntegrated")
fun <I : Nonce> SymmetricEncryptionAlgorithm<AuthType.Authenticated<KeyType.Integrated>, I, KeyType.Integrated>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AuthType.Authenticated.Integrated, I, KeyType.Integrated>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(
            bytes,
            null
        )
    } as KmmResult<SymmetricKey<AuthType.Authenticated.Integrated, I, KeyType.Integrated>>


@JvmName("fixedKeyDedicatedMacKey")
fun <I : Nonce> SymmetricEncryptionAlgorithm<AuthType<KeyType.WithDedicatedMacKey>, I, KeyType.WithDedicatedMacKey>.keyFrom(
    encryptionKey: ByteArray,
    macKey: ByteArray
): KmmResult<SymmetricKey<AuthType<KeyType.WithDedicatedMacKey>, I, KeyType.WithDedicatedMacKey>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *, *>).keyFromInternal(
            encryptionKey,
            macKey
        )
    } as KmmResult<SymmetricKey<AuthType<KeyType.WithDedicatedMacKey>, I, KeyType.WithDedicatedMacKey>>
