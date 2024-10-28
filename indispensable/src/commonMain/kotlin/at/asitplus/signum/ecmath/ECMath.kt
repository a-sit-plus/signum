package at.asitplus.signum.ecmath

import at.asitplus.signum.indispensable.*
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlin.math.max

interface ECMathImpl {
    /** checked in ECMathTest.kt */
    fun checkRequirements(curve: NewECCurve)

    /** addition (not necessarily constant time) */
    fun plus(v: ECPoint, w: ECPoint): ECPoint = ct_plus(v,w)
    /** constant-time point addition */
    fun ct_plus(v: ECPoint, w: ECPoint): ECPoint

    /** adding a point to itself */
    fun double(p: ECPoint): ECPoint = ct_double(p)
    /** constant-time doubling */
    fun ct_double(p: ECPoint): ECPoint

    /** scalar multiplication (not necessarily constant time) */
    fun mul(p: BigInteger, Q: ECPoint) = ct_mul(p,Q)
    /** constant-time scalar multiplication */
    fun ct_mul(p: BigInteger, Q: ECPoint): ECPoint
}

val NewECCurve.math: ECMathImpl inline get() = when (this) {
    ECCurve.SECP_256_R_1, ECCurve.SECP_384_R_1, ECCurve.SECP_521_R_1 -> WeierstrassArithmeticForAEqualsMinus3
}

object WeierstrassArithmeticForAEqualsMinus3: ECMathImpl {
    override fun checkRequirements(curve: NewECCurve) {
        check(curve is WeierstrassCurve)
        check(curve.a == BigInteger(-3).toModularBigInteger(curve.modulus))
    }

    /* Algorithm 4 from https://eprint.iacr.org/2015/1060.pdf */
    override fun ct_plus(v: ECPoint, w: ECPoint): ECPoint {
        val b = v.curve.b
        val X1 = v.homX
        val Y1 = v.homY
        val Z1 = v.homZ
        val X2 = w.homX
        val Y2 = w.homY
        val Z2 = w.homZ
        var t0: ModularBigInteger
        var t1: ModularBigInteger
        var t2: ModularBigInteger
        var t3: ModularBigInteger
        var t4: ModularBigInteger
        var X3: ModularBigInteger
        var Y3: ModularBigInteger
        var Z3: ModularBigInteger
        /*  1. */ t0 = X1 * X2
        /*  2. */ t1 = Y1 * Y2
        /*  3. */ t2 = Z1 * Z2
        /*  4. */ t3 = X1 + Y1
        /*  5. */ t4 = X2 + Y2
        /*  6. */ t3 = t3 * t4
        /*  7. */ t4 = t0 + t1
        /*  8. */ t3 = t3 - t4
        /*  9. */ t4 = Y1 + Z1
        /* 10. */ X3 = Y2 + Z2
        /* 11. */ t4 = t4 * X3
        /* 12. */ X3 = t1 + t2
        /* 13. */ t4 = t4 - X3
        /* 14. */ X3 = X1 + Z1
        /* 15. */ Y3 = X2 + Z2
        /* 16. */ X3 = X3 * Y3
        /* 17. */ Y3 = t0 + t2
        /* 18. */ Y3 = X3 - Y3
        /* 19. */ Z3 = b * t2
        /* 20. */ X3 = Y3 - Z3
        /* 21. */ Z3 = X3 + X3
        /* 22. */ X3 = X3 + Z3
        /* 23. */ Z3 = t1 - X3
        /* 24. */ X3 = t1 + X3
        /* 25. */ Y3 = b * Y3
        /* 26. */ t1 = t2 + t2
        /* 27. */ t2 = t1 + t2
        /* 28. */ Y3 = Y3 - t2
        /* 29. */ Y3 = Y3 - t0
        /* 30. */ t1 = Y3 + Y3
        /* 31. */ Y3 = t1 + Y3
        /* 32. */ t1 = t0 + t0
        /* 33. */ t0 = t1 + t0
        /* 34. */ t0 = t0 - t2
        /* 35. */ t1 = t4 * Y3
        /* 36. */ t2 = t0 * Y3
        /* 37. */ Y3 = X3 * Z3
        /* 38. */ Y3 = Y3 + t2
        /* 39. */ X3 = t3 * X3
        /* 40. */ X3 = X3 - t1
        /* 41. */ Z3 = t4 * Z3
        /* 42. */ t1 = t3 * t0
        /* 43. */ Z3 = Z3 + t1
        return ECPoint.General.unsafeFromXYZ(v.curve, X3, Y3, Z3)
    }

    /* Algorithm 6 from https://eprint.iacr.org/2015/1060.pdf */
    override fun ct_double(p: ECPoint): ECPoint {
        val b = p.curve.b
        val X = p.homX
        val Y = p.homY
        val Z = p.homZ
        var t0: ModularBigInteger
        var t1: ModularBigInteger
        var t2: ModularBigInteger
        var t3: ModularBigInteger
        var X3: ModularBigInteger
        var Y3: ModularBigInteger
        var Z3: ModularBigInteger
        /*  1. */ t0 = X * X
        /*  2. */ t1 = Y * Y
        /*  3. */ t2 = Z * Z
        /*  4. */ t3 = X * Y
        /*  5. */ t3 = t3 + t3
        /*  6. */ Z3 = X * Z
        /*  7. */ Z3 = Z3 + Z3
        /*  8. */ Y3 = b * t2
        /*  9. */ Y3 = Y3 - Z3
        /* 10. */ X3 = Y3 + Y3
        /* 11. */ Y3 = X3 + Y3
        /* 12. */ X3 = t1 - Y3
        /* 13. */ Y3 = t1 + Y3
        /* 14. */ Y3 = X3 * Y3
        /* 15. */ X3 = X3 * t3
        /* 16. */ t3 = t2 + t2
        /* 17. */ t2 = t2 + t3
        /* 18. */ Z3 = b * Z3
        /* 19. */ Z3 = Z3 - t2
        /* 20. */ Z3 = Z3 - t0
        /* 21. */ t3 = Z3 + Z3
        /* 22. */ Z3 = Z3 + t3
        /* 23. */ t3 = t0 + t0
        /* 24. */ t0 = t3 + t0
        /* 25. */ t0 = t0 - t2
        /* 26. */ t0 = t0 * Z3
        /* 27. */ Y3 = Y3 + t0
        /* 28. */ t0 = Y * Z
        /* 29. */ t0 = t0 + t0
        /* 30. */ Z3 = t0 * Z3
        /* 31. */ X3 = X3 - Z3
        /* 32. */ Z3 = t0 * t1
        /* 33. */ Z3 = Z3 + Z3
        /* 34. */ Z3 = Z3 + Z3
        return ECPoint.General.unsafeFromXYZ(p.curve, X3, Y3, Z3)
    }

    // TODO: i'm sure this could be smarter (keyword: "comb")
    override fun mul(p: BigInteger, Q: ECPoint): ECPoint {
        var o = Q
        var sum = if (p.bitAt(0)) Q else Q.curve.IDENTITY
        /* double-and-add */
        for (i in 1L..<p.bitLength()) {
            /* we double o on each iteration (it is (2^i)*point) */
            o = o.double()
            /* and decide whether to add it based on the bit */
            if (p.bitAt(i)) sum += o
        }
        return sum
    }

    override fun ct_mul(p: BigInteger, Q: ECPoint): ECPoint {
        var R0 = Q
        var R1 = Q.double()
        var i = p.bitLength().toLong()-1
        while (--i >= 0) {
            if (p.bitAt(i)) {
                R0 = (R0+R1)
                R1 = R1.double()
            } else {
                R1 = (R0+R1)
                R0 = R0.double()
            }
        }
        return R0
    }
}

/** adds `other` to `this` and returns the result */
inline operator fun ECPoint.plus(other: ECPoint): ECPoint {
    require(this.curve == other.curve)
    return this.curve.math.plus(this, other)
}

inline infix fun ECPoint.ct_plus(other: ECPoint): ECPoint {
    require(this.curve == other.curve)
    return this.curve.math.ct_plus(this, other)
}


/** adds `this` to `this` and returns the result */
inline fun ECPoint.double(): ECPoint {
    return this.curve.math.double(this)
}

/** adds `this` to `this` in constant time and returns the result */
inline fun ECPoint.ct_double(): ECPoint {
    return this.curve.math.ct_double(this)
}

@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.unaryPlus() = this

@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.unaryMinus() =
    ECPoint.General.unsafeFromXYZ(curve, homX, -homY, homZ)

@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.Normalized.unaryMinus() =
    ECPoint.Normalized.unsafeFromXY(curve, x, -y)

@Suppress("NOTHING_TO_INLINE")
inline operator fun ECPoint.minus(other: ECPoint) = this + (-other)

inline infix fun ECPoint.ct_minus(other: ECPoint) = this ct_plus (-other)

inline operator fun BigInteger.times(point: ECPoint) =
    point.curve.math.mul(this, point)

inline infix fun BigInteger.ct_mul(point: ECPoint) =
    point.curve.math.ct_mul(this, point)

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

inline infix fun Int.ct_mul(point: ECPoint) =
    BigInteger.fromInt(this).ct_mul(point)
inline infix fun Long.ct_mul(point: ECPoint) =
    BigInteger.fromLong(this).ct_mul(point)
inline infix fun UInt.ct_mul(point: ECPoint) =
    BigInteger.fromUInt(this).ct_mul(point)
inline infix fun ULong.ct_mul(point: ECPoint) =
    BigInteger.fromULong(this).ct_mul(point)
inline infix fun ModularBigInteger.ct_mul(point: ECPoint): ECPoint {
    require(this.modulus == point.curve.order)
    return this.residue.ct_mul(point)
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
