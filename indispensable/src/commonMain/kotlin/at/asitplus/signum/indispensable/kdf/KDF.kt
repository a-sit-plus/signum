package at.asitplus.signum.indispensable.kdf

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.internals.ByteArrayView
import at.asitplus.signum.internals.isPowerOfTwo
import at.asitplus.signum.internals.subview
import at.asitplus.signum.internals.toLEByteArray
import at.asitplus.signum.internals.toUIntArrayLE


sealed interface KDF

/** RFC 5869 HKDF */
enum class HKDF(val digest: Digest) {
    SHA1(Digest.SHA1),
    SHA256(Digest.SHA256),
    SHA384(Digest.SHA384),
    SHA512(Digest.SHA512);

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

    inner class WithInfo(val info: ByteArray) : KDF {
        val hkdf = this@HKDF
    }
}


class PBKDF2(val prf: HMAC, val iterations: Int) : KDF



/**
 * - CPU/memory [cost] parameter; must be a positive power of two; controls how many independent transformations of the input must be held in memory
 *      affects: scryptROMix
 * - [parallelization] parameter; must be >=1; controls how many blocks scryptROMix is run on in parallel
 *      affects: final key derivation
 * - [blockSize] factor; fine-tunes sequential memory read size and performance. (defaults to `8`, which is commonly used)
 */
class SCrypt(val cost: Int, val parallelization: Int, val blockSize: Int = 8) : KDF {
    init {
        require((cost > 1) && cost.isPowerOfTwo())
        require(parallelization >= 1)
    }

    private val nMinus1 = (cost - 1).toULong()

    fun integerify(B: ByteArrayView): Int =
        ((B[B.size - 64].toUByte().toULong() shl 0) or
                (B[B.size - 63].toUByte().toULong() shl 8) or
                (B[B.size - 62].toUByte().toULong() shl 16) or
                (B[B.size - 61].toUByte().toULong() shl 24) or
                (B[B.size - 60].toUByte().toULong() shl 32) or
                (B[B.size - 59].toUByte().toULong() shl 40) or
                (B[B.size - 58].toUByte().toULong() shl 48) or
                (B[B.size - 57].toUByte().toULong() shl 56)).and(nMinus1).toInt()

    @Suppress("NOTHING_TO_INLINE")
    inner class Mixer {

        @OptIn(ExperimentalUnsignedTypes::class)
        private inline fun R(a: UInt, b: Int) =
            ((a shl b) or (a shr (32 - b)))

        private val salsaInput = UIntArray(16)
        private val salsaScratch = UIntArray(16)
        private inline fun salsa(i1: Int, i2: Int, i3: Int, i4: Int) {
            salsaScratch[i1] = salsaScratch[i1] xor R(salsaScratch[i2] + salsaScratch[i3], 7)
            salsaScratch[i4] = salsaScratch[i4] xor R(salsaScratch[i1] + salsaScratch[i2], 9)
            salsaScratch[i3] = salsaScratch[i3] xor R(salsaScratch[i4] + salsaScratch[i1], 13)
            salsaScratch[i2] = salsaScratch[i2] xor R(salsaScratch[i3] + salsaScratch[i4], 18)
        }

        /** in-place salsa20/8 permutation */
        fun salsa20_8core(block: ByteArrayView) {
            check(block.size == 64)
            block.toUIntArrayLE(salsaInput)
            salsaInput.copyInto(salsaScratch)
            repeat(4) {
                salsa(4, 0, 12, 8)
                salsa(9, 5, 1, 13)
                salsa(14, 10, 6, 2)
                salsa(3, 15, 11, 7)
                salsa(1, 0, 3, 2)
                salsa(6, 5, 4, 7)
                salsa(11, 10, 9, 8)
                salsa(12, 15, 14, 13)
            }
            repeat(16) { salsaScratch[it] += salsaInput[it] }
            salsaScratch.toLEByteArray(block)
        }

        private val y = ByteArray(128 * blockSize)
        fun scryptBlockMix(blocks: ByteArrayView) {
            check(blocks.size == 128 * blockSize)
            var X = blocks.subview(128 * blockSize - 64, 64)
            repeat(2 * blockSize) { i ->
                val Yi = y.subview(64 * i, 64)
                Yi.replaceWith(X)
                Yi.xor_inplace(blocks.subview(64 * i, 64))
                `salsa20_8core`(Yi)
                X = Yi
            }
            repeat(2 * blockSize) { i ->
                blocks.subview(i * 64, 64).replaceWith(
                    when {
                        i < blockSize -> y.subview((2 * i) * 64, 64)
                        else -> y.subview((2 * (i - blockSize) + 1) * 64, 64)
                    }
                )
            }
        }

        private val v = ByteArray(128 * blockSize * cost)
        private val x = ByteArrayView(ByteArray(128 * blockSize))
        fun scryptROMix(bytes: ByteArrayView) {
            check(bytes.size == 128 * blockSize)
            x.replaceWith(bytes)
            repeat(cost) { i ->
                v.subview(i * 128 * blockSize, 128 * blockSize).replaceWith(x)
                scryptBlockMix(x)
            }
            repeat(cost) {
                val j = integerify(x)
                x.xor_inplace(v.subview(j * 128 * blockSize, 128 * blockSize))
                scryptBlockMix(x)
            }
            bytes.replaceWith(x)
        }
    }
}
