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


fun <K : KeyType, A : AuthType< out K>, I : Nonce> SymmetricEncryptionAlgorithm<A, I>.randomKey(): SymmetricKey<A, I,  out K> =
    keyFromInternal(
        secureRandom.nextBytesOf(keySize.bytes.toInt()),
        if (authCapability.keyType is KeyType.WithDedicatedMacKey) secureRandom.nextBytesOf(keySize.bytes.toInt())
        else null
    ) as SymmetricKey<A, I, out K>





@JvmName("randomKeyAndMacKey")
fun <I : Nonce> SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, I>, I>.randomKey(
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
fun SymmetricEncryptionAlgorithm<*, Nonce.Required>.randomNonce(): ByteArray =
    secureRandom.nextBytesOf((nonce.length.bytes).toInt())


private fun SymmetricEncryptionAlgorithm<*, *>.keyFromInternal(
    bytes: ByteArray,
    dedicatedMacKey: ByteArray?
): SymmetricKey<*, *, *> {
    require(bytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${bytes.size * 8}. Required: keySize=${bytes.size.bitLength}" }
    @OptIn(HazardousMaterials::class)
    return when (this.authCapability.keyType) {
        is KeyType.Integrated -> SymmetricKey.Integrated<AuthType<KeyType.Integrated>, Nonce>(
            this as SymmetricEncryptionAlgorithm<AuthType<KeyType.Integrated>, Nonce>,
            bytes
        )

        is KeyType.WithDedicatedMacKey -> SymmetricKey.WithDedicatedMac(
            this as SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, Nonce>, Nonce>,
            bytes,
            dedicatedMacKey!!
        )
    }
}


@JvmName("fixedKeyIntegrated")
fun <I : Nonce> SymmetricEncryptionAlgorithm<AuthType<KeyType.Integrated>, I>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AuthType<KeyType.Integrated>, I, KeyType.Integrated>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *>).keyFromInternal(
            bytes,
            null
        )
    } as KmmResult<SymmetricKey<AuthType<KeyType.Integrated>, I, KeyType.Integrated>>


@JvmName("fixedKeyDedicatedMacKey")
fun <I : Nonce> SymmetricEncryptionAlgorithm<AuthType<KeyType.WithDedicatedMacKey>, I>.keyFrom(
    encryptionKey: ByteArray,
    macKey: ByteArray
): KmmResult<SymmetricKey<AuthType<KeyType.WithDedicatedMacKey>, I, KeyType.WithDedicatedMacKey>> =
    catching {
        (this as SymmetricEncryptionAlgorithm<*, *>).keyFromInternal(
            encryptionKey,
            macKey
        )
    } as KmmResult<SymmetricKey<AuthType<KeyType.WithDedicatedMacKey>, I, KeyType.WithDedicatedMacKey>>
