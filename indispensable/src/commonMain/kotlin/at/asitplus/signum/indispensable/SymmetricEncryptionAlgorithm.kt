package at.asitplus.signum.indispensable

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import kotlin.jvm.JvmName


fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>.sealedBox(
    iv: ByteArray,
    encryptedBytes: ByteArray
) =
    SealedBox.WithIV<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>>(
        iv,
        Ciphertext.Unauthenticated(
            this,
            encryptedBytes
        ) as Ciphertext<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>>
    )

@JvmName("sealedBoxAuthenticatedDedicated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>.sealedBox(
    iv: ByteArray,
    encryptedBytes: ByteArray,
    authTag: ByteArray,
    aad: ByteArray? = null
) = (this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>).sealedBox(
    iv,
    encryptedBytes,
    authTag,
    aad
) as SealedBox.WithIV<CipherKind.Authenticated.WithDedicatedMac<*,IV.Required>, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*,IV.Required>, IV.Required>>

@JvmName("sealedBoxAuthenticated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>.sealedBox(
    iv: ByteArray,
    encryptedBytes: ByteArray,
    authTag: ByteArray,
    aad: ByteArray? = null
) =
    SealedBox.WithIV<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>(
        iv,
        when (this.cipher) {
            is CipherKind.Authenticated.WithDedicatedMac<*, *> ->
                Ciphertext.Authenticated.WithDedicatedMac(
                    this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>,
                    encryptedBytes,
                    authTag,
                    aad
                )

            is CipherKind.Authenticated.Integrated ->
                Ciphertext.Authenticated.Integrated(
                    this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>,
                    encryptedBytes,
                    authTag,
                    aad
                )
        } as Ciphertext<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>>
    )

sealed interface SymmetricEncryptionAlgorithm<out A : CipherKind, out I : IV> :
    Identifiable {
    val cipher: A
    val iv: I

    override fun toString(): String

    companion object {

        val AES_128 = AESDefinition(128.bit)
        val AES_192 = AESDefinition(192.bit)
        val AES_256 = AESDefinition(256.bit)

        class AESDefinition(val keySize: BitLength) {

            val GCM = AES.GCM(keySize)
            val CBC = CbcDefinition(keySize)

            class CbcDefinition(keySize: BitLength) {
                @HazardousMaterials
                val PLAIN = AES.CBC.Plain(keySize)

                @OptIn(HazardousMaterials::class)
                val HMAC = HmacDefinition(PLAIN)

                class HmacDefinition(innerCipher: AES.CBC.Plain) {
                    val SHA_256 = AES.CBC.HMAC(innerCipher, HMAC.SHA256)
                    val SHA_384 = AES.CBC.HMAC(innerCipher, HMAC.SHA384)
                    val SHA_512 = AES.CBC.HMAC(innerCipher, HMAC.SHA512)
                    val SHA_1 = AES.CBC.HMAC(innerCipher, HMAC.SHA1)
                }
            }
        }
    }

    /**Humanly-readable name**/
    val name: String

    /**
     * Key length in bits
     */
    val keySize: BitLength

    sealed class AES<A : CipherKind>(modeOfOps: ModeOfOperation, override val keySize: BitLength) :
        BlockCipher<A, IV.Required>(modeOfOps, blockSize = 128.bit) {
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keySize: BitLength) :
            AES<CipherKind.Authenticated.Integrated>(ModeOfOperation.GCM, keySize) {
            override val iv = IV.Required(96.bit)
            override val cipher = CipherKind.Authenticated.Integrated(blockSize)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }
        }

        sealed class CBC<A : CipherKind>(keySize: BitLength) : AES<A>(ModeOfOperation.CBC, keySize) {
            override val iv = IV.Required(128u.bit)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }

            class Plain(
                keySize: BitLength
            ) : CBC<CipherKind.Unauthenticated>(keySize) {
                override val cipher = CipherKind.Unauthenticated
                override val name = super.name + " Plain"
            }

            class HMAC(innerCipher: Plain, mac: at.asitplus.signum.indispensable.mac.HMAC) :
                CBC<CipherKind.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, IV.Required>>(
                    innerCipher.keySize
                ) {
                override val cipher =
                    CipherKind.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, IV.Required>(
                        innerCipher,
                        mac,
                        mac.outputLength
                    )
                override val name = super.name + " $mac"
            }
        }
    }
}

/**
 * Defines whether a cipher is authenticated or not
 */
sealed interface CipherKind {
    /**
     * Indicates an authenticated cipher
     */
    sealed class Authenticated(val tagLen: BitLength) : CipherKind {

        /**
         * An authenticated cipher construction that is inherently authenticated
         */
        class Integrated(tagLen: BitLength) : Authenticated(tagLen)

        /**
         * An authenticated cipher construction based on an unauthenticated cipher with a dedicated MAC function.
         */
        class WithDedicatedMac<M : MAC, I : IV>(
            val innerCipher: SymmetricEncryptionAlgorithm<Unauthenticated, I>,
            val mac: M,
            tagLen: BitLength
        ) : Authenticated(tagLen)
    }

    /**
     * Indicates an unauthenticated cipher
     */
    object Unauthenticated : CipherKind
}

sealed class IV {
    /**
     * Indicates that a cipher requires an initialization vector
     */
    class Required(val ivLen: BitLength) : IV()

    object Without : IV()
}

sealed class BlockCipher<A : CipherKind, I : IV>(
    val mode: ModeOfOperation,
    val blockSize: BitLength
) : SymmetricEncryptionAlgorithm<A, I> {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipherblock Chaining Mode", "CBC"),
    }
}