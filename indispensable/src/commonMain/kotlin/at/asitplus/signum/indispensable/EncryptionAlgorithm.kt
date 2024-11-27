package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.AuthTrait.Authenticated
import at.asitplus.signum.indispensable.AuthTrait.Unauthenticated
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier


sealed interface EncryptionAlgorithm<out A: AuthTrait> : Identifiable {
    override fun toString(): String

    companion object {

        val AES_128 = AESDefinition(128u)
        val AES_192 = AESDefinition(192u)
        val AES_256 = AESDefinition(256u)

        class AESDefinition(private val keySize: UInt) {

            val GCM = AES.GCM(keySize)
            val CBC = CbcDefinition(keySize)

            class CbcDefinition(private val keySize: UInt) {
                val PLAIN = AES.CBC.Plain(keySize)
                val HMAC = HmacDefinition(keySize)

                class HmacDefinition(private val keySize: UInt) {
                    val SHA_256 = AES.CBC.HMAC(keySize, Digest.SHA256)
                    val SHA_384 = AES.CBC.HMAC(keySize, Digest.SHA384)
                    val SHA_512 = AES.CBC.HMAC(keySize, Digest.SHA512)
                    val SHA_1 = AES.CBC.HMAC(keySize, Digest.SHA1)
                }
            }
        }


        /*
                val AES128_ECB = AES.ECB(128u)
                val AES192_ECB = AES.ECB(192u)
                val AES256_ECB = AES.ECB(256u)*/
    }

    val name: String


    /**
     * Indicates that a cipher requires an initialization vector
     */
    interface WithIV<A: AuthTrait> : EncryptionAlgorithm<A> {
        val ivNumBits: UInt
    }

    interface Authenticated: EncryptionAlgorithm<AuthTrait.Authenticated>, AuthTrait.Authenticated
    interface Unauthenticated: EncryptionAlgorithm<AuthTrait.Unauthenticated>, AuthTrait.Unauthenticated

    /**
     * Key length in bits
     */
    val keyNumBits: UInt

    sealed class AES<A: AuthTrait>(modeOfOps: ModeOfOperation, override val keyNumBits: UInt) :
        BlockCipher<A>(modeOfOps, blockSizeBits = 128u) {
        override val name: String = "AES-$keyNumBits ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keyNumBits: UInt) : AES<AuthTrait.Authenticated>(ModeOfOperation.GCM, keyNumBits), WithIV<AuthTrait.Authenticated>, Authenticated {
            override val ivNumBits: UInt = 96u
            override val tagNumBits: UInt = blockSizeBits
            override val oid: ObjectIdentifier = when (keyNumBits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw IllegalStateException("$keyNumBits This is an implementation flaw. Report this bug!")
            }
        }

        sealed class CBC<A: AuthTrait>(keyNumBits: UInt) : AES<A> (ModeOfOperation.CBC, keyNumBits), WithIV<A> {
            override val ivNumBits: UInt = 128u
            override val oid: ObjectIdentifier = when (keyNumBits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw IllegalStateException("$keyNumBits This is an implementation flaw. Report this bug!")
            }

            class Plain(keyNumBits: UInt) : CBC<AuthTrait.Unauthenticated>(keyNumBits), WithIV<AuthTrait.Unauthenticated>, Unauthenticated

            class HMAC(keyNumBits: UInt, val digest: Digest) : CBC<AuthTrait.Authenticated>(keyNumBits), WithIV<AuthTrait.Authenticated>, Authenticated {
                override val tagNumBits: UInt = blockSizeBits
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
interface AuthTrait {
    /**
     * Indicates an authenticated cipher
     */
    interface Authenticated : AuthTrait {
        val tagNumBits: UInt
    }

    /**
     * Indicates an unauthenticated cipher
     */
    interface Unauthenticated: AuthTrait
}

sealed class BlockCipher<A: AuthTrait>(val mode: ModeOfOperation, val blockSizeBits: UInt) : EncryptionAlgorithm<A> {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipherblock Chaining Mode", "CBC"),
        //ECB("Electronic Codebook Mode", "ECB"),

    }
}