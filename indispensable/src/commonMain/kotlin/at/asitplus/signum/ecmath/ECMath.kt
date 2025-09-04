package at.asitplus.signum.ecmath

import at.asitplus.signum.indispensable.ECPoint
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlin.math.max

// ECMathNIST -> https://eprint.iacr.org/2015/1060
// TODO eddsa https://datatracker.ietf.org/doc/html/rfc8032
// TODO brainpool https://datatracker.ietf.org/doc/html/rfc5639
interface ECMath
{
    fun plus(point1: ECPoint, point2: ECPoint): ECPoint

    fun double(point: ECPoint): ECPoint

    fun unaryMinus(point: ECPoint): ECPoint

    fun unaryMinus(point: ECPoint.Normalized): ECPoint.Normalized
}


@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.plus(other: ECPoint): ECPoint
    = this.curve.ecMathImplementation.plus(this,other)

@Suppress("NOTHING_TO_INLINE")
inline fun ECPoint.double(): ECPoint
    = this.curve.ecMathImplementation.double(this)

@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.unaryPlus() = this

@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.unaryMinus()
    = this.curve.ecMathImplementation.unaryMinus(this)

@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.Normalized.unaryMinus()
    = this.curve.ecMathImplementation.unaryMinus(this)

@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.minus(other: ECPoint) = this + (-other)

// TODO: i'm sure this could be smarter (keyword: "comb")
// i'm also sure this isn't resistant to timing side channels if that is something you care about
// TODO Manfred: two comments how to implement constant time (provided that "x = if(a) b else c" performs constant time)
// TODO there is also another timing problem with ModularBigInteger as it internally uses BigInteger and time can depend on value - should be implemented fixed number of bytes
operator fun BigInteger.times(point: ECPoint): ECPoint {
    var o = point // Manfred: I would rename the point to "p" (or q,r,...) ; in ECC context the symbol "o" or "O" is commonly for the neutral element/identity (since it looks+behaves like the origin/zero, i.e., p+o = p for every p)
    var sum = if (this.bitAt(0)) point else point.curve.IDENTITY
    /* double-and-add */
    for (i in 1L..<this.bitLength()) { // TODO Manfred 1: instead of BigInter we should use ModularBigInteger or make use of the group order of the curve -> has a fixed number of bits -> fixed number of loop-iterations, independent from the input
        /* we double o on each iteration (it is (2^i)*point) */
        o = o.double()
        /* and decide whether to add it based on the bit */
        if (this.bitAt(i)) sum += o  // TODO Manfred 2: "sum += if (bit) o else point.curve.IDENTITY"
    }
    return sum
}

@Suppress("NOTHING_TO_INLINE")
inline operator fun Int.times(point: ECPoint) =
    BigInteger.fromInt(this).times(point)

@Suppress("NOTHING_TO_INLINE")
inline operator fun Long.times(point: ECPoint) =
    BigInteger.fromLong(this).times(point)

@Suppress("NOTHING_TO_INLINE")
inline operator fun UInt.times(point: ECPoint) =
    BigInteger.fromUInt(this).times(point)

@Suppress("NOTHING_TO_INLINE")
inline operator fun ULong.times(point: ECPoint) =
    BigInteger.fromULong(this).times(point)

@Suppress("NOTHING_TO_INLINE")
inline operator fun ModularBigInteger.times(point: ECPoint): ECPoint {
    require(this.modulus == point.curve.order)
    return this.residue.times(point)
}

/* these are intentionally not operator functions! */
@Suppress("NOTHING_TO_INLINE")
inline fun ECPoint.times(v: BigInteger) = v * this

@Suppress("NOTHING_TO_INLINE")
inline fun ECPoint.times(v: ModularBigInteger) = v * this

@Suppress("NOTHING_TO_INLINE")
inline fun ECPoint.times(v: Int) = v * this

@Suppress("NOTHING_TO_INLINE")
inline fun ECPoint.times(v: UInt) = v * this

@Suppress("NOTHING_TO_INLINE")
inline fun ECPoint.times(v: Long) = v * this

@Suppress("NOTHING_TO_INLINE")
inline fun ECPoint.times(v: ULong) = v * this

/** computes uG+vQ */
fun straussShamir(u: BigInteger, G: ECPoint, v: BigInteger, Q: ECPoint): ECPoint {
    val H = G+Q
    val uL = u.bitLength()
    val vL = v.bitLength()
    var i = max(uL,vL).toLong()-1
    var R = if(uL > vL) G else if (uL < vL) Q else H
    while (--i >= 0) {
        R = R.double()
        val b = u.bitAt(i)
        val c = v.bitAt(i)
        if (b && c) R += H
        else if (b) R += G
        else if (c) R += Q
    }
    return R
}

/** computes pQ in constant time */
fun montgomeryMul(k: BigInteger, P: ECPoint): ECPoint {
    var R0 = P
    var R1 = P.double()
    var i = k.bitLength().toLong()-1
    while (--i >= 0) {
        if (k.bitAt(i)) {
            R0 = (R0+R1)
            R1 = R1.double()
        } else {
            R1 = (R0+R1)
            R0 = R0.double()
        }
    }
    return R0
}
