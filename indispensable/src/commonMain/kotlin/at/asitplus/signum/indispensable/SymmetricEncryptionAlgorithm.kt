package at.asitplus.signum.indispensable

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit


sealed interface SymmetricEncryptionAlgorithm<out A : AuthTrait> : Identifiable, AuthTrait {
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

    /**Humanly-readable nam**/
    val name: String


    /**
     * Indicates that a cipher requires an initialization vector
     */
    interface WithIV<A : AuthTrait> : SymmetricEncryptionAlgorithm<A> {
        val ivLen: BitLength
    }

    sealed interface Authenticated<M: AuthTrait.Authenticated> : SymmetricEncryptionAlgorithm<M>, AuthTrait.Authenticated {
        interface Integrated: Authenticated<AuthTrait.Authenticated.Integrated>
        interface WithDedicatedMac : Authenticated<AuthTrait.Authenticated.WithDedicatedMac> {
            val mac: MAC
            val innerCipher: SymmetricEncryptionAlgorithm.Unauthenticated
        }
    }
    interface Unauthenticated : SymmetricEncryptionAlgorithm<AuthTrait.Unauthenticated>, AuthTrait.Unauthenticated

    /**
     * Key length in bits
     */
    val keySize: BitLength

    sealed class AES<A : AuthTrait>(modeOfOps: ModeOfOperation, override val keySize: BitLength) :
        BlockCipher<A>(modeOfOps, blockSizeBits = 128u), WithIV<A> {
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keySize: BitLength) :
            AES<AuthTrait.Authenticated.Integrated>(ModeOfOperation.GCM, keySize),
            Authenticated.Integrated {
            override val ivLen = 96u.bit
            override val tagNumBits: UInt = blockSizeBits
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }
        }

        sealed class CBC<A : AuthTrait>(keySize: BitLength) : AES<A>(ModeOfOperation.CBC, keySize) {
            override val ivLen = 128u.bit
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }

            class Plain(keySize: BitLength) : CBC<AuthTrait.Unauthenticated>(keySize),
                Unauthenticated {
                override val name = super.name+ " Plain"
                }

            class HMAC(override val innerCipher: Plain, override val mac: MAC) :
                CBC<AuthTrait.Authenticated.WithDedicatedMac>(innerCipher.keySize),
                Authenticated.WithDedicatedMac {
                override val tagNumBits: UInt = mac.outputLength.toUInt() * 8u

                override val name = super.name+ " $mac"
            }
        }
    }
}

/**
 * Defines whether a cipher is authenticated or not
 */
sealed interface AuthTrait {
    /**
     * Indicates an authenticated cipher
     */
    sealed interface Authenticated : AuthTrait {
        val tagNumBits: UInt

        interface Integrated : Authenticated
        interface WithDedicatedMac : Authenticated
    }

    /**
     * Indicates an unauthenticated cipher
     */
    interface Unauthenticated : AuthTrait
}

sealed class BlockCipher<A : AuthTrait>(val mode: ModeOfOperation, val blockSizeBits: UInt) : SymmetricEncryptionAlgorithm<A> {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipherblock Chaining Mode", "CBC"),
    }
}