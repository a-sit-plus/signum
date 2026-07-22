package at.asitplus.signum.indispensable.kdf

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.integrity.HMAC
import at.asitplus.signum.internals.isPowerOfTwo

/**
 * [RFC 5869](https://tools.ietf.org/html/rfc5869) HKDF using an [HMAC] based on the passed [digest].
 *
 * To obtain an actual [KDF] for key derivation, invoke as `(info = ...)`
 * */
class HKDF(val digest: Digest) {

    companion object {
        val SHA1 = HKDF(WellKnownDigest.SHA1)
        val SHA256 = HKDF(WellKnownDigest.SHA256)
        val SHA384 = HKDF(WellKnownDigest.SHA384)
        val SHA512 = HKDF(WellKnownDigest.SHA512)
    }

    /**
     * Creates a fully instantiated HKDF object with info
     */
    operator fun invoke(info: ByteArray) = WithInfo(info)

    val hmac = HMAC.entries.first { it.digest == digest }

    val outputLength: Int get() = digest.outputLength.bytes.toInt()

    /**
     * The actual [HKDF] instance configured with [info] set.
     */
    inner class WithInfo internal constructor(val info: ByteArray) : KDF {
        val hkdf get() = this@HKDF
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithInfo) return false

            if (!info.contentEquals(other.info)) return false
            if (hkdf != other.hkdf) return false

            return true
        }

        override fun hashCode(): Int {
            var result = info.contentHashCode()
            result = 31 * result + hkdf.hashCode()
            return result
        }
    }
}

/**
 *  [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018)-compliant PBKDF2 template using an [HMAC] as its [prf] (pseudo-random function).
 *
 *  To obtain an actual [KDF] for key derivation, invoke as `(iterations = ...)`
 */
class PBKDF2(val prf: HMAC) {

    constructor(digest: Digest) : this(HMAC(digest))

    operator fun invoke(iterations: Int) = WithIterations(iterations)

    companion object {
        val HMAC_SHA1 = PBKDF2(HMAC.SHA1)
        val HMAC_SHA256 = PBKDF2(HMAC.SHA256)
        val HMAC_SHA384 = PBKDF2(HMAC.SHA384)
        val HMAC_SHA512 = PBKDF2(HMAC.SHA512)

    }

    /**
     * The actual [PBKDF2] instance configured with [iterations] set.
     */
    inner class WithIterations internal constructor(val iterations: Int) : KDF {
        val pbkdf2 = this@PBKDF2
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithIterations) return false

            if (iterations != other.iterations) return false
            if (pbkdf2 != other.pbkdf2) return false

            return true
        }

        override fun hashCode(): Int {
            var result = iterations
            result = 31 * result + pbkdf2.hashCode()
            return result
        }
    }
}


/**
 * `scrypt` in accordance with [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914). Directly implements the [KDF] interface.
 *
 * Parameters:
 * - CPU/memory [cost] parameter; must be a positive power of two greater than 1; controls how many independent transformations of the input must be held in memory
 *     * affects: `scryptBlockMix`
 * - [parallelization] parameter; must be >=1; controls how many blocks `scryptROMix` is run on in parallel
 *     * affects: final key derivation
 * - [blockSize] factor; must be >=1; fine-tunes sequential memory read size and performance. Defaults to `8`, which is commonly used.
 *     * affects: `scryptBlockMix` and `scryptROMix`
 */
class SCrypt(val cost: Int, val parallelization: Int, val blockSize: Int = 8) : KDF {
    init {
        require((cost > 1) && cost.isPowerOfTwo()) { "cost must be a positive power of two" }
        require(parallelization >= 1) { "parallelization must be >=1" }
        require(blockSize >= 1) { "blockSize must be >=1" }
    }
}
