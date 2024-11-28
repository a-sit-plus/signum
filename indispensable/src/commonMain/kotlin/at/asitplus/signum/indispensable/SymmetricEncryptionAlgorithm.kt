package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MAC


sealed interface SymmetricEncryptionAlgorithm<out A : AuthTrait> : Identifiable {
    override fun toString(): String

    companion object {

        val AES_128 = AESDefinition(128u)
        val AES_192 = AESDefinition(192u)
        val AES_256 = AESDefinition(256u)

        class AESDefinition(val keySize: UInt) {

            val GCM = AES.GCM(keySize)
            val CBC = CbcDefinition(keySize)

            class CbcDefinition(keySize: UInt) {
                val PLAIN = AES.CBC.Plain(keySize)
                val HMAC = HmacDefinition(PLAIN)

                class HmacDefinition(innerCipher: AES.CBC.Plain) {
                    val SHA_256 = AES.CBC.HMAC(innerCipher, HMAC.SHA256)
                    val SHA_384 = AES.CBC.HMAC(innerCipher, HMAC.SHA384)
                    val SHA_512 = AES.CBC.HMAC(innerCipher, HMAC.SHA512)
                    val SHA_1 = AES.CBC.HMAC(innerCipher, HMAC.SHA1)
                }
            }
        }


        /*
                val AES128_ECB = AES.ECB(128u)
                val AES192_ECB = AES.ECB(192u)
                val AES256_ECB = AES.ECB(256u)*/
    }

    val name: String


    interface WithDedicatedMac : Authenticated, WithIV<AuthTrait.Authenticated> {
        val mac: MAC
        val innerCipher: SymmetricEncryptionAlgorithm.Unauthenticated
    }

    /**
     * Indicates that a cipher requires an initialization vector
     */
    interface WithIV<A : AuthTrait> : SymmetricEncryptionAlgorithm<A> {
        val ivNumBits: UInt
    }

    interface Authenticated : SymmetricEncryptionAlgorithm<AuthTrait.Authenticated>, AuthTrait.Authenticated
    interface Unauthenticated : SymmetricEncryptionAlgorithm<AuthTrait.Unauthenticated>, AuthTrait.Unauthenticated

    /**
     * Key length in bits
     */
    val keyNumBits: UInt

    sealed class AES<A : AuthTrait>(modeOfOps: ModeOfOperation, override val keyNumBits: UInt) :
        BlockCipher<A>(modeOfOps, blockSizeBits = 128u) {
        override val name: String = "AES-$keyNumBits ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keyNumBits: UInt) :
            AES<AuthTrait.Authenticated>(ModeOfOperation.GCM, keyNumBits), WithIV<AuthTrait.Authenticated>,
            Authenticated {
            override val ivNumBits: UInt = 96u
            override val tagNumBits: UInt = blockSizeBits
            override val oid: ObjectIdentifier = when (keyNumBits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw IllegalStateException("$keyNumBits This is an implementation flaw. Report this bug!")
            }
        }

        sealed class CBC<A : AuthTrait>(keyNumBits: UInt) : AES<A>(ModeOfOperation.CBC, keyNumBits), WithIV<A> {
            override val ivNumBits: UInt = 128u
            override val oid: ObjectIdentifier = when (keyNumBits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw IllegalStateException("$keyNumBits This is an implementation flaw. Report this bug!")
            }

            class Plain(keyNumBits: UInt) : CBC<AuthTrait.Unauthenticated>(keyNumBits),
                WithIV<AuthTrait.Unauthenticated>, Unauthenticated {
                override val name = super.name+ " Plain"
                }

            class HMAC(override val innerCipher: Plain, override val mac: MAC) :
                CBC<AuthTrait.Authenticated>(innerCipher.keyNumBits), WithIV<AuthTrait.Authenticated>, WithDedicatedMac,
                Authenticated {
                override val tagNumBits: UInt = mac.Nm.toUInt() * 8u

                override val name = super.name+ " $mac"
            }
        }

        /*class ECB(keyNumBits: UInt) : AES(ModeOfOperation.ECB, keyNumBits){
            override val oid: ObjectIdentifier = when (keyNumBits) {
                128u -> KnownOIDs.aes128_ECB
                192u -> KnownOIDs.aes192_ECB
                256u -> KnownOIDs.aes256_ECB
                else -> throw IllegalStateException("$keyNumBits This is an implementation flaw. Report this bug!")
            }
        } */
    }
}

/**
 * Defines whether a cipher is authenticated or not
 */
sealed interface AuthTrait {
    /**
     * Indicates an authenticated cipher
     */
    interface Authenticated : AuthTrait {
        val tagNumBits: UInt
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
        //ECB("Electronic Codebook Mode", "ECB"),

    }
}