package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.CipherKind
import at.asitplus.signum.indispensable.symmetric.IV
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.indispensable.asn1.encoding.bitLength
import kotlin.jvm.JvmName

fun SymmetricEncryptionAlgorithm<*, *>.randomKey(): SymmetricKey<*, *> =
    encryptionKeyFrom(secureRandom.nextBytesOf(keySize.bytes.toInt())).getOrThrow()

@JvmName("randomKeyWithIV")
fun SymmetricEncryptionAlgorithm<*, IV.Required>.randomKey(): SymmetricKey<*, IV.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<*, IV.Required>

@JvmName("randomKeyUnauthenticated")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>.randomKey(): SymmetricKey<CipherKind.Unauthenticated, *> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<CipherKind.Unauthenticated, *>

@JvmName("randomKeyUnauthenticatedWithIV")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>.randomKey(): SymmetricKey<CipherKind.Unauthenticated, IV.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<CipherKind.Unauthenticated, IV.Required>

@JvmName("randomKeyAuthenticatedIntegrated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>.randomKey(): SymmetricKey<CipherKind.Authenticated.Integrated, *> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<CipherKind.Authenticated.Integrated, *>

@JvmName("randomKeyAuthenticatedIntegratedWithIV")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, IV.Required>.randomKey(): SymmetricKey<CipherKind.Authenticated.Integrated, IV.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<CipherKind.Authenticated.Integrated, IV.Required>

@JvmName("randomKeyAuthenticatedWithDedicatedMacWithIV")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>.randomKey(
    dedicatedMacKeyOverride: ByteArray? = null
): SymmetricKey.WithDedicatedMac<IV.Required> =
    (this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>).randomKey(
        dedicatedMacKeyOverride = dedicatedMacKeyOverride
    ) as SymmetricKey.WithDedicatedMac<IV.Required>

@JvmName("randomKeyAuthenticatedWithDedicatedMAC")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>.randomKey(dedicatedMacKeyOverride: ByteArray? = null): SymmetricKey<CipherKind.Authenticated.WithDedicatedMac<*, *>, *> {
    val secretKey = secureRandom.nextBytesOf(keySize.bytes.toInt())
    @OptIn(HazardousMaterials::class)
    return SymmetricKey.WithDedicatedMac<IV>(
        this,
        secretKey = secretKey,
        dedicatedMacKey = dedicatedMacKeyOverride ?: secretKey
    )
}

/**
 * Generates a new random IV matching the IV size of this algorithm
 */
internal fun SymmetricEncryptionAlgorithm<*, IV.Required>.randomIV() =
    @OptIn(HazardousMaterials::class) secureRandom.nextBytesOf((iv.ivLen.bytes).toInt())


fun SymmetricEncryptionAlgorithm<*, *>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<*, *>> =
    catching {
        require(keyBytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${keyBytes.size * 8}. Required: keySize=${keyBytes.size.bitLength}" }
        @OptIn(HazardousMaterials::class)
        when (this.cipher) {
            is CipherKind.Authenticated.Integrated, is CipherKind.Unauthenticated -> SymmetricKey.Integrated(
                this,
                keyBytes
            )

            is CipherKind.Authenticated.WithDedicatedMac<*, *> -> SymmetricKey.WithDedicatedMac(
                this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>,
                keyBytes
            )
        }
    }


@JvmName("fixedKeyWithIV")
fun SymmetricEncryptionAlgorithm<*, IV.Required>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<*, IV.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<*, IV.Required>>

@JvmName("fixedKeyUnauthenticated")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<CipherKind.Unauthenticated, *>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<CipherKind.Unauthenticated, *>>

@JvmName("fixedKeyUnauthenticatedWithIV")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<CipherKind.Unauthenticated, IV.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<CipherKind.Unauthenticated, IV.Required>>

@JvmName("fixedKeyAuthenticatedIntegrated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<CipherKind.Authenticated.Integrated, *>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<CipherKind.Authenticated.Integrated, *>>

@JvmName("fixedKeyAuthenticatedIntegratedWithIV")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, IV.Required>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<CipherKind.Authenticated.Integrated, IV.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<CipherKind.Authenticated.Integrated, IV.Required>>

@JvmName("fixedKeyAuthenticatedWithDedicatedMacWithIV")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>.encryptionKeyFrom(
    keyBytes: ByteArray,
    dedicatedMacKeyOverride: ByteArray? = null
): KmmResult<SymmetricKey.WithDedicatedMac<IV.Required>> =
    (this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>).encryptionKeyFrom(
        keyBytes,
        dedicatedMacKeyOverride = dedicatedMacKeyOverride
    ) as KmmResult<SymmetricKey.WithDedicatedMac<IV.Required>>

@JvmName("fixedKeyAuthenticatedWithDedicatedMAC")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>.encryptionKeyFrom(
    keyBytes: ByteArray,
    dedicatedMacKeyOverride: ByteArray? = null
): KmmResult<SymmetricKey<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>> = catching {
    require(keyBytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${keyBytes.size * 8}. Required: keySize=${keyBytes.size.bitLength}" }
    @OptIn(HazardousMaterials::class)
    SymmetricKey.WithDedicatedMac<IV>(
        this,
        secretKey = keyBytes,
        dedicatedMacKey = dedicatedMacKeyOverride ?: keyBytes
    )
}