package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.CipherKind
import at.asitplus.signum.indispensable.symmetric.Nonce
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.indispensable.asn1.encoding.bitLength
import kotlin.jvm.JvmName

fun SymmetricEncryptionAlgorithm<*, *>.randomKey(): SymmetricKey<*, *> =
    encryptionKeyFrom(secureRandom.nextBytesOf(keySize.bytes.toInt())).getOrThrow()

@JvmName("randomKeyWithNonce")
fun <A: CipherKind>SymmetricEncryptionAlgorithm<A, Nonce.Required>.randomKey(): SymmetricKey<A, Nonce.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<A, Nonce.Required>

@JvmName("randomKeyUnauthenticated")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>.randomKey(): SymmetricKey<CipherKind.Unauthenticated, *> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<CipherKind.Unauthenticated, *>

@JvmName("randomKeyUnauthenticatedWithNonce")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Required>.randomKey(): SymmetricKey<CipherKind.Unauthenticated, Nonce.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<CipherKind.Unauthenticated, Nonce.Required>

@JvmName("randomKeyAuthenticatedIntegrated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>.randomKey(): SymmetricKey<CipherKind.Authenticated.Integrated, *> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<CipherKind.Authenticated.Integrated, *>

@JvmName("randomKeyAuthenticatedIntegratedWithNonce")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, Nonce.Required>.randomKey(): SymmetricKey<CipherKind.Authenticated.Integrated, Nonce.Required> =
    (this as SymmetricEncryptionAlgorithm<*, *>).randomKey() as SymmetricKey<CipherKind.Authenticated.Integrated, Nonce.Required>

@JvmName("randomKeyAuthenticatedWithDedicatedMacWithNonce")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>.randomKey(
    dedicatedMacKeyOverride: ByteArray? = null
): SymmetricKey.WithDedicatedMac<Nonce.Required> =
    (this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>).randomKey(
        dedicatedMacKeyOverride = dedicatedMacKeyOverride
    ) as SymmetricKey.WithDedicatedMac<Nonce.Required>

@JvmName("randomKeyAuthenticatedWithDedicatedMAC")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>.randomKey(dedicatedMacKeyOverride: ByteArray? = null): SymmetricKey<CipherKind.Authenticated.WithDedicatedMac<*, *>, *> {
    val secretKey = secureRandom.nextBytesOf(keySize.bytes.toInt())
    @OptIn(HazardousMaterials::class)
    return SymmetricKey.WithDedicatedMac<Nonce>(
        this,
        secretKey = secretKey,
        dedicatedMacKey = dedicatedMacKeyOverride ?: secretKey
    )
}

/**
 * Generates a new random Nonce matching the Nonce size of this algorithm
 */
internal fun SymmetricEncryptionAlgorithm<*, Nonce.Required>.randomNonce() =
    @OptIn(HazardousMaterials::class) secureRandom.nextBytesOf((nonce.length.bytes).toInt())


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


@JvmName("fixedKeyWithNonce")
fun SymmetricEncryptionAlgorithm<*, Nonce.Required>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<*, Nonce.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<*, Nonce.Required>>

@JvmName("fixedKeyUnauthenticated")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<CipherKind.Unauthenticated, *>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<CipherKind.Unauthenticated, *>>

@JvmName("fixedKeyUnauthenticatedWithNonce")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Required>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<CipherKind.Unauthenticated, Nonce.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<CipherKind.Unauthenticated, Nonce.Required>>

@JvmName("fixedKeyAuthenticatedIntegrated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<CipherKind.Authenticated.Integrated, *>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<CipherKind.Authenticated.Integrated, *>>

@JvmName("fixedKeyAuthenticatedIntegratedWithNonce")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, Nonce.Required>.encryptionKeyFrom(keyBytes: ByteArray): KmmResult<SymmetricKey<CipherKind.Authenticated.Integrated, Nonce.Required>> =
    (this as SymmetricEncryptionAlgorithm<*, *>).encryptionKeyFrom(keyBytes) as KmmResult<SymmetricKey<CipherKind.Authenticated.Integrated, Nonce.Required>>

@JvmName("fixedKeyAuthenticatedWithDedicatedMacWithNonce")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>.encryptionKeyFrom(
    keyBytes: ByteArray,
    dedicatedMacKeyOverride: ByteArray? = null
): KmmResult<SymmetricKey.WithDedicatedMac<Nonce.Required>> =
    (this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>).encryptionKeyFrom(
        keyBytes,
        dedicatedMacKeyOverride = dedicatedMacKeyOverride
    ) as KmmResult<SymmetricKey.WithDedicatedMac<Nonce.Required>>

@JvmName("fixedKeyAuthenticatedWithDedicatedMAC")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>.encryptionKeyFrom(
    keyBytes: ByteArray,
    dedicatedMacKeyOverride: ByteArray? = null
): KmmResult<SymmetricKey<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>> = catching {
    require(keyBytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${keyBytes.size * 8}. Required: keySize=${keyBytes.size.bitLength}" }
    @OptIn(HazardousMaterials::class)
    SymmetricKey.WithDedicatedMac<Nonce>(
        this,
        secretKey = keyBytes,
        dedicatedMacKey = dedicatedMacKeyOverride ?: keyBytes
    )
}