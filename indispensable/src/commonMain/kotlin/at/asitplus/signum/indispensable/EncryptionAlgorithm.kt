package at.asitplus.signum.indispensable

sealed interface EncryptionAlgorithm {

    companion object {
        val AES128_GCM = AES.GCM(128u)
        val AES192_GCM = AES.GCM(192u)
        val AES256_GCM = AES.GCM(256u)

        val AES128_CBC_HMAC256 = AES.CBC(256u)
        val AES128_CBC_HMAC384 = AES.CBC(348u)
        val AES128_CBC_HMAC512 = AES.CBC(512u)

        val AES128_ECB = AES.ECB(128u)
        val AES192_ECB = AES.ECB(192u)
        val AES256_ECB = AES.ECB(256u)
    }

    /**
     * Indicates that a cipher uses a discrete message authentication code
     */
    interface Authenticated {
        val tagNumBits: UInt
    }

    /**
     * Indicates that a cipher requires an initialization vector
     */
    interface WithIV {
        val ivNumBits: UInt
    }

    /**
     * Key length in bits
     */
    val keyNumBits: UInt

    sealed class AES(modeOfOps: ModeOfOperation, override val keyNumBits: UInt) :
        BlockCipher(modeOfOps, blockSizeBits = 128u) {

        class GCM(keyNumBits: UInt) : AES(ModeOfOperation.GCM, keyNumBits), WithIV, Authenticated {
            override val ivNumBits: UInt = 96u
            override val tagNumBits: UInt = blockSizeBits
        }

        class CBC(keyNumBits: UInt) : AES(ModeOfOperation.GCM, keyNumBits), WithIV, Authenticated {
            override val ivNumBits: UInt = 128u
            override val tagNumBits: UInt = blockSizeBits
        }

        class ECB(keyNumBits: UInt) : AES(ModeOfOperation.ECB, keyNumBits)
    }
}

sealed class BlockCipher(val mode: ModeOfOperation, val blockSizeBits: UInt) : EncryptionAlgorithm {

    enum class ModeOfOperation(val friendlyName: String) {
        GCM("Galois Counter Mode"),
        CBC("Cipherblock Chaining Mode"),
        ECB("Electronic Codebook Mode"),

    }
}