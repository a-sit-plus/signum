package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.encoding.bitLength
import at.asitplus.signum.indispensable.symmetric.AECapability
import at.asitplus.signum.indispensable.symmetric.Nonce
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import org.kotlincrypto.SecureRandom
import kotlin.jvm.JvmName

private val secureRandom = SecureRandom()


fun SymmetricEncryptionAlgorithm<*, *>.randomKey(): SymmetricKey<*, *> =
    keyFrom(secureRandom.nextBytesOf(keySize.bytes.toInt())).getOrThrow()

@JvmName("randomKeyWithNonce")
fun <A : AECapability> SymmetricEncryptionAlgorithm<A, Nonce.Required>.randomKey(): SymmetricKey<A, Nonce.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<A, Nonce.Required>

@JvmName("randomKeyUnauthenticated")
fun SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>.randomKey(): SymmetricKey<AECapability.Unauthenticated, *> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<AECapability.Unauthenticated, *>

@JvmName("randomKeyUnauthenticatedWithNonce")
fun SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Required>.randomKey(): SymmetricKey<AECapability.Unauthenticated, Nonce.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<AECapability.Unauthenticated, Nonce.Required>

@JvmName("randomKeyAuthenticatedIntegrated")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.Integrated, *>.randomKey(): SymmetricKey<AECapability.Authenticated.Integrated, *> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<AECapability.Authenticated.Integrated, *>

@JvmName("randomKeyAuthenticatedIntegratedWithNonce")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.Integrated, Nonce.Required>.randomKey(): SymmetricKey<AECapability.Authenticated.Integrated, Nonce.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<AECapability.Authenticated.Integrated, Nonce.Required>

@JvmName("randomKeyAuthenticatedWithDedicatedMacWithNonce")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>.randomKey(
    dedicatedMacKeyOverride: ByteArray? = null
): SymmetricKey.WithDedicatedMac<Nonce.Required> =
    (this as SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, *>, *>).randomKey(
        dedicatedMacKeyOverride = dedicatedMacKeyOverride
    ) as SymmetricKey.WithDedicatedMac<Nonce.Required>

@JvmName("randomKeyAuthenticatedWithDedicatedMAC")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, *>, *>.randomKey(dedicatedMacKeyOverride: ByteArray? = null): SymmetricKey<AECapability.Authenticated.WithDedicatedMac<*, *>, *> {
    val secretKey = secureRandom.nextBytesOf(keySize.bytes.toInt())
    @OptIn(HazardousMaterials::class)
    return SymmetricKey.WithDedicatedMac<Nonce>(
        this,
        secretKey = secretKey,
        dedicatedMacKey = dedicatedMacKeyOverride ?: secretKey
    )
}

/**
 * Generates a new random Nonce matching the Nonce size of this algorithm.
 * You typically don't want to use this, but have your nonces auto-generated.
 */
@HazardousMaterials("Don't explicitly generate nonces!")
 fun SymmetricEncryptionAlgorithm<*, Nonce.Required>.randomNonce() =
    secureRandom.nextBytesOf((nonce.length.bytes).toInt())


fun SymmetricEncryptionAlgorithm<*, *>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<*, *>> =
    catching {
        require(bytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${bytes.size * 8}. Required: keySize=${bytes.size.bitLength}" }
        @OptIn(HazardousMaterials::class)
        when (this.cipher) {
            is AECapability.Authenticated.Integrated, is AECapability.Unauthenticated -> SymmetricKey.Integrated(
                this,
                bytes
            )

            is AECapability.Authenticated.WithDedicatedMac<*, *> -> SymmetricKey.WithDedicatedMac(
                this as SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, *>, *>,
                bytes
            )
        }
    }


@JvmName("fixedKeyWithNonce")
fun SymmetricEncryptionAlgorithm<*, Nonce.Required>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<*, Nonce.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).keyFrom(bytes) as KmmResult<SymmetricKey<*, Nonce.Required>>

@JvmName("fixedKeyUnauthenticated")
fun SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AECapability.Unauthenticated, *>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).keyFrom(bytes) as KmmResult<SymmetricKey<AECapability.Unauthenticated, *>>

@JvmName("fixedKeyUnauthenticatedWithNonce")
fun SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Required>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AECapability.Unauthenticated, Nonce.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).keyFrom(bytes) as KmmResult<SymmetricKey<AECapability.Unauthenticated, Nonce.Required>>

@JvmName("fixedKeyAuthenticatedIntegrated")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.Integrated, *>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AECapability.Authenticated.Integrated, *>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).keyFrom(bytes) as KmmResult<SymmetricKey<AECapability.Authenticated.Integrated, *>>

@JvmName("fixedKeyAuthenticatedIntegratedWithNonce")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.Integrated, Nonce.Required>.keyFrom(bytes: ByteArray): KmmResult<SymmetricKey<AECapability.Authenticated.Integrated, Nonce.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).keyFrom(bytes) as KmmResult<SymmetricKey<AECapability.Authenticated.Integrated, Nonce.Required>>

@JvmName("fixedKeyAuthenticatedWithDedicatedMacWithNonce")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>.keyFrom(
    bytes: ByteArray,
    dedicatedMacKeyOverride: ByteArray? = null
): KmmResult<SymmetricKey.WithDedicatedMac<Nonce.Required>> =
    (this as SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, *>, *>).keyFrom(
        bytes,
        dedicatedMacKeyOverride = dedicatedMacKeyOverride
    ) as KmmResult<SymmetricKey.WithDedicatedMac<Nonce.Required>>

@JvmName("fixedKeyAuthenticatedWithDedicatedMAC")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, *>, *>.keyFrom(
    bytes: ByteArray,
    dedicatedMacKeyOverride: ByteArray? = null
): KmmResult<SymmetricKey<AECapability.Authenticated.WithDedicatedMac<*, *>, *>> = catching {
    require(bytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${bytes.size * 8}. Required: keySize=${bytes.size.bitLength}" }
    @OptIn(HazardousMaterials::class)
    SymmetricKey.WithDedicatedMac<Nonce>(
        this,
        secretKey = bytes,
        dedicatedMacKey = dedicatedMacKeyOverride ?: bytes
    )
}