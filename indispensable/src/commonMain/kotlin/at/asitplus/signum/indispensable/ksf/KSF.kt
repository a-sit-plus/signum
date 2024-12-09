@file:OptIn(ExperimentalUnsignedTypes::class)
package at.asitplus.signum.indispensable.ksf

import at.asitplus.signum.internals.ByteArrayView
import at.asitplus.signum.internals.subview
import at.asitplus.signum.internals.isPowerOfTwo
import at.asitplus.signum.internals.toLEByteArray
import at.asitplus.signum.internals.toUIntArrayLE

sealed interface KSF

/**
 * r - Block size parameter
 * N - CPU/memory cost parameter; controls how many independent transformations of the input must be held in memory
 *      affects: scryptROMix
 * p - parallelization parameter; controls how many blocks scryptROMix is run on in parallel
 *      affects: scrypt
 */
class SCrypt(val N: Int, val r: Int, val p: Int): KSF {
    init {
        require ((N > 1) && N.isPowerOfTwo())
    }

    private val nMinus1 = (N-1).toULong()

    fun integerify(B: ByteArrayView): Int =
        ((B[B.size-64].toUByte().toULong() shl 0) or
                (B[B.size-63].toUByte().toULong() shl 8) or
                (B[B.size-62].toUByte().toULong() shl 16) or
                (B[B.size-61].toUByte().toULong() shl 24) or
                (B[B.size-60].toUByte().toULong() shl 32) or
                (B[B.size-59].toUByte().toULong() shl 40) or
                (B[B.size-58].toUByte().toULong() shl 48) or
                (B[B.size-57].toUByte().toULong() shl 56)).and(nMinus1).toInt()

    inner class Mixer {

        @OptIn(ExperimentalUnsignedTypes::class)
        private inline fun R(a: UInt, b: Int) =
            ((a shl b) or (a shr (32-b)))

        private val salsaInput = UIntArray(16)
        private val salsaScratch = UIntArray(16)
        private inline fun salsa(i1: Int, i2: Int, i3: Int, i4: Int) {
            salsaScratch[i1] = salsaScratch[i1] xor R(salsaScratch[i2]+salsaScratch[i3], 7)
            salsaScratch[i4] = salsaScratch[i4] xor R(salsaScratch[i1]+salsaScratch[i2], 9)
            salsaScratch[i3] = salsaScratch[i3] xor R(salsaScratch[i4]+salsaScratch[i1], 13)
            salsaScratch[i2] = salsaScratch[i2] xor R(salsaScratch[i3]+salsaScratch[i4], 18)
        }
        /** in-place salsa20/8 permutation */
        fun `Salsa20∕8 Core`(B: ByteArrayView) {
            check(B.size == 64)
            B.toUIntArrayLE(salsaInput)
            salsaInput.copyInto(salsaScratch)
            repeat(4) {
                salsa(4,0,12, 8)
                salsa(9,5,1,13)
                salsa(14,10,6,2)
                salsa(3,15,11,7)
                salsa(1,0,3,2)
                salsa(6,5,4,7)
                salsa(11,10,9,8)
                salsa(12,15,14,13)
            }
            repeat(16) { salsaScratch[it] += salsaInput[it] }
            salsaScratch.toLEByteArray(B)
        }

        private val y = ByteArray(128*r)
        fun scryptBlockMix(B: ByteArrayView) {
            check(B.size == 128*r)
            var X = B.subview(128*r-64, 64)
            repeat(2*r) { i ->
                val Yi = y.subview(64*i,64)
                Yi.replaceWith(X)
                Yi.xor_inplace(B.subview(64*i,64))
                `Salsa20∕8 Core`(Yi)
                X = Yi
            }
            repeat(2*r) { i ->
                B.subview(i*64,64).replaceWith(when {
                    i < r -> y.subview((2*i)*64, 64)
                    else -> y.subview((2*(i-r)+1)*64, 64)
                })
            }
        }

        private val v = ByteArray(128*r*N)
        private val x = ByteArrayView(ByteArray(128*r))
        fun scryptROMix(bytes: ByteArrayView) {
            check(bytes.size == 128*r)
            x.replaceWith(bytes)
            repeat(N) { i ->
                v.subview(i*128*r, 128*r).replaceWith(x)
                scryptBlockMix(x)
            }
            repeat(N) {
                val j = integerify(x)
                x.xor_inplace(v.subview(j*128*r, 128*r))
                scryptBlockMix(x)
            }
            bytes.replaceWith(x)
        }
    }
}
