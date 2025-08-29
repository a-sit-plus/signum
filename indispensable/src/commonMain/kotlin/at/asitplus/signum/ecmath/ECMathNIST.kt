package at.asitplus.signum.ecmath

import at.asitplus.signum.indispensable.ECPoint
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.modular.ModularBigInteger

// following https://eprint.iacr.org/2015/1060.pdf
class ECMathNIST: ECMath {

    /** adds `point2` to `point1` and returns the result */
    /* Algorithm 4 from https://eprint.iacr.org/2015/1060.pdf */
    override fun plus(
        point1: ECPoint,
        point2: ECPoint
    ): ECPoint {
        require(point1.curve == point2.curve)
        val b = point1.curve.b
        val X1 = point1.homX
        val Y1 = point1.homY
        val Z1 = point1.homZ
        val X2 = point2.homX
        val Y2 = point2.homY
        val Z2 = point2.homZ
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
        return ECPoint.General.unsafeFromXYZ(point1.curve, X3, Y3, Z3)
    }

    /** adds `point` to `point` and returns the result */
    /* Algorithm 6 from https://eprint.iacr.org/2015/1060.pdf */
    override fun double(point: ECPoint): ECPoint {
        val b = point.curve.b
        val X = point.homX
        val Y = point.homY
        val Z = point.homZ
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
        return ECPoint.General.unsafeFromXYZ(point.curve, X3, Y3, Z3)
    }

    override fun unaryMinus(point: ECPoint): ECPoint
      = ECPoint.General.unsafeFromXYZ(point.curve, point.homX, -point.homY, point.homZ)

    override fun unaryMinus(point: ECPoint.Normalized)
      = ECPoint.Normalized.unsafeFromXY(point.curve, point.x, -point.y)
}