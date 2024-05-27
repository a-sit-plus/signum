package at.asitplus.crypto.datatypes.misc

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.jvm.JvmInline

@JvmInline
value class BitLength (val bits: UInt): Comparable<BitLength> {
    inline val bytes: UInt get() =
        bits.floorDiv(8u) + (if(bits.rem(8u) != 0u) 1u else 0u)

    companion object {
        inline fun of(v: BigInteger) = BitLength(v.bitLength().toUInt())
    }

    inline override fun compareTo(other: BitLength): Int =
        bits.compareTo(other.bits)

}

inline fun min(a: BitLength, b: BitLength) =
    if (a.bits < b.bits) a else b

inline fun max(a: BitLength, b: BitLength) =
    if (a.bits < b.bits) b else a
