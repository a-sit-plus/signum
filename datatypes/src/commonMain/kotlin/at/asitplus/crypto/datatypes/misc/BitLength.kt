package at.asitplus.crypto.datatypes.misc

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.jvm.JvmInline

@JvmInline
value class BitLength (val bits: UInt) {
    inline val bytes: UInt get() =
        bits.floorDiv(8u) + (if(bits.rem(8u) != 0u) 1u else 0u)

    companion object {
        inline fun of(v: BigInteger) = BitLength(v.bitLength().toUInt())
    }
}
