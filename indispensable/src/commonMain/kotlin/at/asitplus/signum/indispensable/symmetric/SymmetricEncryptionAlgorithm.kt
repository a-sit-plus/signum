package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import kotlin.jvm.JvmName

@JvmName("sealedUnauthedBoxWithIV")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>.sealedBox(
    iv: ByteArray,
    encryptedData: ByteArray
) = SealedBox.WithIV<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>>(
    iv,
    Ciphertext.Unauthenticated(
        this,
        encryptedData
    ) as Ciphertext<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>>
)

fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Without>.sealedBox(
    encryptedData: ByteArray
) =
    SealedBox.WithoutIV<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Without>>(
        Ciphertext.Unauthenticated(
            this,
            encryptedData
        ) as Ciphertext<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Without>>
    )

@JvmName("sealedBoxAuthenticatedDedicated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>.sealedBox(
    iv: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = (this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated, IV.Required>).sealedBox(
    iv,
    encryptedData,
    authTag,
    authenticatedData
) as SealedBox.WithIV<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>

@JvmName("sealedBoxAuthenticated")
fun <A : CipherKind.Authenticated> SymmetricEncryptionAlgorithm<A, IV.Required>.sealedBox(
    iv: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = SealedBox.WithIV<A, SymmetricEncryptionAlgorithm<A, IV.Required>>(
    iv,
    authenticatedCipherText(encryptedData, authTag, authenticatedData)
)

@JvmName("sealedBoxAuthenticated")
fun <A : CipherKind.Authenticated> SymmetricEncryptionAlgorithm<A, IV.Without>.sealedBox(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = SealedBox.WithoutIV<A, SymmetricEncryptionAlgorithm<A, IV.Without>>(
    authenticatedCipherText(encryptedData, authTag, authenticatedData)
)


private inline fun <A : CipherKind.Authenticated, reified I : IV> SymmetricEncryptionAlgorithm<A, I>.authenticatedCipherText(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = Ciphertext.Authenticated<A, SymmetricEncryptionAlgorithm<A, I>>(
    this,
    encryptedData,
    authTag,
    authenticatedData
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

            class HMAC
            private constructor(
                innerCipher: Plain,
                mac: at.asitplus.signum.indispensable.mac.HMAC,
                dedicatedMacInputCalculation: DedicatedMacInputCalculation
            ) :
                CBC<CipherKind.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, IV.Required>>(
                    innerCipher.keySize
                ) {
                constructor(innerCipher: Plain, mac: at.asitplus.signum.indispensable.mac.HMAC) : this(
                    innerCipher,
                    mac,
                    DefaultDedicatedMacInputCalculation
                )

                override val cipher =
                    CipherKind.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, IV.Required>(
                        innerCipher,
                        mac,
                        mac.outputLength,
                        dedicatedMacInputCalculation
                    )
                override val name = super.name + " $mac"

                /**
                 * Instantiates a new [CBC.HMAC] with a custom [dedicatedMacInputCalculation]
                 */
                fun Custom(dedicatedMacInputCalculation: DedicatedMacInputCalculation) =
                    CBC.HMAC(cipher.innerCipher as Plain, cipher.mac, dedicatedMacInputCalculation)
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
            tagLen: BitLength,
            val dedicatedMacInputCalculation: DedicatedMacInputCalculation
        ) : Authenticated(tagLen)
    }

    /**
     * Indicates an unauthenticated cipher
     */
    object Unauthenticated : CipherKind
}

/**
 * Typealias defining the signature of the lambda for defining a custom MAC input calculation scheme.
 */
typealias DedicatedMacInputCalculation = MAC.(ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray?) -> ByteArray

/**
 * The default dedicated mac input calculation:
 * ```kotlin
 * (iv?: byteArrayOf()) + (aad ?: byteArrayOf()) + ciphertext
 * ```
 */
val DefaultDedicatedMacInputCalculation: DedicatedMacInputCalculation =
    fun MAC.(ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray?): ByteArray =
        (iv ?: byteArrayOf()) + (aad ?: byteArrayOf()) + ciphertext


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