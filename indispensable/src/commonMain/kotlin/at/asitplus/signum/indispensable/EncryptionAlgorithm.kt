package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier


sealed interface EncryptionAlgorithm : Identifiable {
    override fun toString(): String

    companion object {
        val AES128_GCM = AES.GCM(128u)
        val AES192_GCM = AES.GCM(192u)
        val AES256_GCM = AES.GCM(256u)

        val AES128_CBC_HMAC256 = AES.CBC(128u)
        val AES128_CBC_HMAC384 = AES.CBC(192u)
        val AES128_CBC_HMAC512 = AES.CBC(256u)

        val AES128_ECB = AES.ECB(128u)
        val AES192_ECB = AES.ECB(192u)
        val AES256_ECB = AES.ECB(256u)
    }

    val name: String

    /**
     * Indicates an authenticated cipher
     */
    interface Authenticated : EncryptionAlgorithm {
        val tagNumBits: UInt
    }

    /**
     * Indicates that a cipher requires an initialization vector
     */
    interface WithIV : EncryptionAlgorithm {
        val ivNumBits: UInt
    }

    /**
     * Key length in bits
     */
    val keyNumBits: UInt

    sealed class AES(modeOfOps: ModeOfOperation, override val keyNumBits: UInt) :
        BlockCipher(modeOfOps, blockSizeBits = 128u) {
        override val name: String = "AES-$keyNumBits ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keyNumBits: UInt) : AES(ModeOfOperation.GCM, keyNumBits), WithIV, Authenticated {
            override val ivNumBits: UInt = 96u
            override val tagNumBits: UInt = blockSizeBits
            override val oid: ObjectIdentifier = when (keyNumBits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw IllegalStateException("$keyNumBits This is an implementation flaw. Report this bug!")
            }
        }

        class CBC(keyNumBits: UInt) : AES(ModeOfOperation.CBC, keyNumBits), WithIV, Authenticated {
            override val ivNumBits: UInt = 128u
            override val tagNumBits: UInt = blockSizeBits
            override val oid: ObjectIdentifier = when (keyNumBits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw IllegalStateException("$keyNumBits This is an implementation flaw. Report this bug!")
            }
        }

        class ECB(keyNumBits: UInt) : AES(ModeOfOperation.ECB, keyNumBits){
            override val oid: ObjectIdentifier = when (keyNumBits) {
                128u -> KnownOIDs.aes128_ECB
                192u -> KnownOIDs.aes192_ECB
                256u -> KnownOIDs.aes256_ECB
                else -> throw IllegalStateException("$keyNumBits This is an implementation flaw. Report this bug!")
            }
        }
    }
}

sealed class BlockCipher(val mode: ModeOfOperation, val blockSizeBits: UInt) : EncryptionAlgorithm {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipherblock Chaining Mode", "CBC"),
        ECB("Electronic Codebook Mode", "ECB"),

    }
}