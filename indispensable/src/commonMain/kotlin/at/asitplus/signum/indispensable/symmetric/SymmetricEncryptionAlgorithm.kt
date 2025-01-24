package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo8Bytes
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit


sealed interface SymmetricEncryptionAlgorithm<out A : AECapability, out I : Nonce> :
    Identifiable {
    val cipher: A
    val nonce: I

    override fun toString(): String

    companion object {
        //ChaChaPoly is already an object, so we don't need to redeclare here

        val AES_128 = AESDefinition(128.bit)
        val AES_192 = AESDefinition(192.bit)
        val AES_256 = AESDefinition(256.bit)

        /**
         * AES configuration hierarchy
         */
        class AESDefinition(val keySize: BitLength) {

            val GCM = AES.GCM(keySize)
            val CBC = CbcDefinition(keySize)

            class CbcDefinition(keySize: BitLength) {
                @HazardousMaterials
                val PLAIN = AES.CBC.Unauthenticated(keySize)

                @OptIn(HazardousMaterials::class)
                val HMAC = HmacDefinition(PLAIN)

                class HmacDefinition(innerCipher: AES.CBC.Unauthenticated) {
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

    /**
     * Advanced Encryption Standard
     */
    sealed class AES<A : AECapability>(modeOfOps: ModeOfOperation, override val keySize: BitLength) :
        BlockCipher<A, Nonce.Required>(modeOfOps, blockSize = 128.bit) {
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keySize: BitLength) :
            AES<AECapability.Authenticated.Integrated>(ModeOfOperation.GCM, keySize) {
            override val nonce = Nonce.Required(96.bit)
            override val cipher = AECapability.Authenticated.Integrated(blockSize)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }
        }

        sealed class CBC<A : AECapability>(keySize: BitLength) : AES<A>(ModeOfOperation.CBC, keySize) {
            override val nonce = Nonce.Required(128u.bit)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }

            class Unauthenticated(
                keySize: BitLength
            ) : CBC<AECapability.Unauthenticated>(keySize) {
                override val cipher = AECapability.Unauthenticated
                override val name = super.name + " Plain"
            }

            /**
             * AEAD-capabilities bolted onto AES-CBC
             */
            class HMAC
            private constructor(
                innerCipher: Unauthenticated,
                mac: at.asitplus.signum.indispensable.mac.HMAC,
                dedicatedMacInputCalculation: DedicatedMacInputCalculation
            ) :
                CBC<AECapability.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, Nonce.Required>>(
                    innerCipher.keySize
                ) {
                constructor(innerCipher: Unauthenticated, mac: at.asitplus.signum.indispensable.mac.HMAC) : this(
                    innerCipher,
                    mac,
                    DefaultDedicatedMacInputCalculation
                )

                override val cipher =
                    AECapability.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, Nonce.Required>(
                        innerCipher,
                        mac,
                        mac.outputLength,
                        dedicatedMacInputCalculation
                    )
                override val name = super.name + " $mac"

                /**
                 * Instantiates a new [CBC.HMAC] instance with a custom [DedicatedMacInputCalculation]
                 */
                fun Custom(dedicatedMacInputCalculation: DedicatedMacInputCalculation) =
                    CBC.HMAC(cipher.innerCipher as Unauthenticated, cipher.mac, dedicatedMacInputCalculation)
            }
        }
    }

    object ChaCha20Poly1305 : StreamCipher<AECapability.Authenticated, Nonce.Required>() {
        override val cipher = AECapability.Authenticated.Integrated(128u.bit)
        override val nonce = Nonce.Required(96u.bit)
        override val name: String = "ChaCha20-Poly1305"
        override fun toString() = name
        override val keySize = 256u.bit
        override val oid = KnownOIDs.chaCha20Poly1305
    }
}

/**
 * Defines whether a cipher is authenticated or not
 */
sealed interface AECapability {
    /**
     * Indicates an authenticated cipher
     */
    sealed class Authenticated(val tagLen: BitLength) : AECapability {

        /**
         * An authenticated cipher construction that is inherently authenticated
         */
        class Integrated(tagLen: BitLength) : Authenticated(tagLen)

        /**
         * An authenticated cipher construction based on an unauthenticated cipher with a dedicated MAC function.
         */
        class WithDedicatedMac<M : MAC, I : Nonce>(
            val innerCipher: SymmetricEncryptionAlgorithm<Unauthenticated, I>,
            val mac: M,
            tagLen: BitLength,
            val dedicatedMacInputCalculation: DedicatedMacInputCalculation
        ) : Authenticated(tagLen)
    }

    /**
     * Indicates an unauthenticated cipher
     */
    object Unauthenticated : AECapability
}

/**
 * Typealias defining the signature of the lambda for defining a custom MAC input calculation scheme.
 */
typealias DedicatedMacInputCalculation = MAC.(ciphertext: ByteArray, nonce: ByteArray?, aad: ByteArray?) -> ByteArray

/**
 * The default dedicated mac input calculation, analogous to TLS 1.2 AES-CBC-HMAC:
 * ```kotlin
 * (aad ?: byteArrayOf()) + ciphertext
 * ```
 */
val DefaultDedicatedMacInputCalculation: DedicatedMacInputCalculation =
    fun MAC.(ciphertext: ByteArray, nonce: ByteArray?, aad: ByteArray?): ByteArray = (aad ?: byteArrayOf()) + ciphertext

/**
 * RFC 7518 (AES_CBC_HMAC_SHA2) MAC input calculation:
 * `AAD || 0x2E || IV || Ciphertext || 0x2E || AAD_Length`, where AAD_length is a 64 bit big-endian
 */
val RFC7518DedicatedMacInputCalculation: DedicatedMacInputCalculation =
    fun MAC.(ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray?): ByteArray =
        (aad ?: byteArrayOf()) + 0x2E + (iv ?: byteArrayOf()) + ciphertext + 0x2E +
                (aad?.size?.toLong()?.encodeTo8Bytes() ?: byteArrayOf())

sealed class Nonce {
    /**
     * Indicates that a cipher requires an initialization vector
     */
    class Required(val length: BitLength) : Nonce()

    object Without : Nonce()
}

sealed class BlockCipher<A : AECapability, I : Nonce>(
    val mode: ModeOfOperation,
    val blockSize: BitLength
) : SymmetricEncryptionAlgorithm<A, I> {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipherblock Chaining Mode", "CBC"),
    }
}

sealed class StreamCipher<A : AECapability, I : Nonce> : SymmetricEncryptionAlgorithm<A, I>