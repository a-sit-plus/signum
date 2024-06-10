package at.asitplus.crypto.datatypes.misc

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.jvm.JvmInline

/**
 * Utility class to represent the bit length of curves and signatures.
 *
 * Should be a value class, but the Swift export becomes impossible.
 */
data class BitLength (val bits: UInt): Comparable<BitLength> {
    inline val bytes: UInt get() =
        bits.floorDiv(8u) + (if(bits.rem(8u) != 0u) 1u else 0u)

    companion object {
        @Suppress("NOTHING_TO_INLINE")
        inline fun of(v: BigInteger) = BitLength(v.bitLength().toUInt())
    }

    @Suppress("NOTHING_TO_INLINE", "OVERRIDE_BY_INLINE")
    override inline fun compareTo(other: BitLength): Int =
        bits.compareTo(other.bits)
}

@Suppress("NOTHING_TO_INLINE")
inline fun min(a: BitLength, b: BitLength) =
    if (a.bits < b.bits) a else b

@Suppress("NOTHING_TO_INLINE")
inline fun max(a: BitLength, b: BitLength) =
    if (a.bits < b.bits) b else a
