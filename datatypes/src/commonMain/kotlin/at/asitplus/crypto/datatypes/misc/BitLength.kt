package at.asitplus.crypto.datatypes.misc

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.jvm.JvmInline

/**
 * Utility class to represent the bit length of curves and signatures.
 *
 * Should be a value class, but the Swift export becomes impossible.
 */
data class BitLength(val bits: UInt) : Comparable<BitLength> {
    inline val bytes: UInt get() =
        bits.floorDiv(8u) + (if (bits.rem(8u) != 0u) 1u else 0u)
    /** how many bits are unused padding to get to the next full byte */
    inline val bitSpacing: UInt get() =
        bits.rem(8u).let { if (it != 0u) (8u-it) else 0u }

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

val UInt.bit inline get() = BitLength(this)
val Int.bit inline get() = this.toUInt().bit
val UInt.bytes inline get() = BitLength(8u*this)
val Int.bytes inline get() = this.toUInt().bytes
