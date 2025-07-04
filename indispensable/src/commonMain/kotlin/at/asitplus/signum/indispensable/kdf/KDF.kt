package at.asitplus.signum.indispensable.kdf

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.kdf.PBKDF2.WithIterations
import at.asitplus.signum.internals.*


sealed interface KDF

/**
 * [RFC 5869](https://tools.ietf.org/html/rfc5869) HKDF using an [HMAC] based on the passed [digest].
 *
 * Create an instance of [WithInfo] to obtain an actual [KDF] for key derivation.
 * */
enum class HKDF(val digest: Digest) {
    SHA1(Digest.SHA1),
    SHA256(Digest.SHA256),
    SHA384(Digest.SHA384),
    SHA512(Digest.SHA512);

    /**
     * Creates a fully instantiated HKDF object with info
     */
    operator fun invoke(info: ByteArray) = WithInfo(info)

    companion object {
        operator fun invoke(digest: Digest) = when (digest) {
            Digest.SHA1 -> SHA1
            Digest.SHA256 -> SHA256
            Digest.SHA384 -> SHA384
            Digest.SHA512 -> SHA512
        }
    }

    val hmac = HMAC.entries.first { it.digest == digest }

    val outputLength: Int get() = digest.outputLength.bytes.toInt()

    /**
     * The actual [HKDF] instance configured with [info] set.
     */
    inner class WithInfo internal constructor(val info: ByteArray) : KDF {
        val hkdf = this@HKDF
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
 *  Create an instance of [WithIterations] to obtain an actual [KDF] for key derivation.
 */
enum class PBKDF2(val prf: HMAC) {
    HMAC_SHA1(HMAC.SHA1),
    HMAC_SHA256(HMAC.SHA256),
    HMAC_SHA384(HMAC.SHA384),
    HMAC_SHA512(HMAC.SHA512);

    operator fun invoke(iterations: Int) = WithIterations(iterations)

    companion object {
        operator fun invoke(prf: HMAC) = when (prf) {
            HMAC.SHA1 -> HMAC_SHA1
            HMAC.SHA256 -> HMAC_SHA256
            HMAC.SHA384 -> HMAC_SHA384
            HMAC.SHA512 -> HMAC_SHA512
        }

        operator fun invoke(digest: Digest) = invoke(HMAC(digest))

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
