package at.asitplus.signum.indispensable

import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.compressY
import at.asitplus.signum.indispensable.misc.decompressY
import com.ionspin.kotlin.bignum.BigNumber
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.jvm.JvmSynthetic

private fun BigNumber.Creator<ModularBigInteger>.fromByteArray(v: ByteArray) =
    fromBigInteger(BigInteger.fromByteArray(v, Sign.POSITIVE))

/** A short-Weierstrass curve over a prime field, with equation y² = x³ + ax + b. */
@Serializable(with = ShortWeierstrassCurveSerializer::class)
interface ShortWeierstrassCurve : ECCurve {
    val jwkName: String
    val modulus: BigInteger
    val a: ModularBigInteger
    val b: ModularBigInteger
    val generator: Point.Normalized
    val coordinateCreator: BigNumber.Creator<ModularBigInteger>
    val scalarCreator: BigNumber.Creator<ModularBigInteger>

    val IDENTITY: Point
        get() = with(coordinateCreator) { Point.General.unsafeFromXYZ(this@ShortWeierstrassCurve, ZERO, ONE, ZERO) }
    val coordinateLength: BitLength get() = BitLength.of(modulus)

    /**
     * A point on a short-Weierstrass curve in homogeneous coordinates (X, Y, Z).
     * Normalize finite points to access their affine coordinates.
     * @see normalize
     * @see tryNormalize
     */
    sealed class Point private constructor(
        /** the curve on which this point lies */
        override val curve: ShortWeierstrassCurve,
        /**
         * homogeneous X coordinate of point (X : Y : Z)
         * @see normalize
         */
        val homX: ModularBigInteger,
        /**
         * homogeneous Y coordinate of point (X : Y : Z)
         * @see normalize
         */
        val homY: ModularBigInteger,
        /**
         * homogeneous Z coordinate of point (X : Y : Z)
         * @see normalize
         */
        val homZ: ModularBigInteger
    ) : ECPoint {

        class General private constructor(
            c: ShortWeierstrassCurve, hX: ModularBigInteger, hY: ModularBigInteger, hZ: ModularBigInteger
        ) : Point(c, hX, hY, hZ) {
            companion object {
                @PublishedApi
                @JvmSynthetic
                internal fun unsafeFromXYZ(c: ShortWeierstrassCurve, x: ModularBigInteger, y: ModularBigInteger, z: ModularBigInteger) =
                    General(c, x, y, z)
            }
        }

        /** normalized elliptic curve point (Z = 1). cannot be the point at infinity. */
        @Serializable(with = ECPointSerializer::class)
        class Normalized private constructor(
            curve: ShortWeierstrassCurve,
            x: ModularBigInteger,
            y: ModularBigInteger
        ) : Point(curve, x, y, curve.coordinateCreator.ONE) {
            /** x coordinate of the point (x,y) */
            val x inline get() = homX

            /** y coordinate of the point (x,y) */
            val y inline get() = homY

            val xBytes inline get() = x.toByteArray().ensureSize(curve.coordinateLength.bytes)
            val yBytes inline get() = y.toByteArray().ensureSize(curve.coordinateLength.bytes)
            val yCompressed get() = compressY(curve, x, y)

            override fun hashCode() = (31 * (31 * curve.hashCode()) + x.hashCode()) + y.hashCode()

            companion object {
                @PublishedApi
                @JvmSynthetic
                internal fun unsafeFromXY(curve: ShortWeierstrassCurve, x: ModularBigInteger, y: ModularBigInteger) =
                    Normalized(curve, x, y)
            }
        }

        override fun toString() =
            if (isPointAtInfinity)
                "ECPoint[$curve]: Point at Infinity"
            else if (this is Normalized)
                "ECPoint[$curve]: (${homX.toString(16)} : ${homY.toString(16)}) [normalized]"
            else
                "ECPoint[$curve]: (${(homX/homZ).toString(16)} : ${(homY/homZ).toString(16)}) [with Z = ${homZ.toString(16)}]"

        override fun equals(other: Any?): Boolean {
            if (other !is Point) return false
            if (this.curve !== other.curve) return false
            if (this.isPointAtInfinity) return other.isPointAtInfinity
            if (this.homZ == other.homZ) return ((this.homX == other.homX) && (this.homY == other.homY))

            return (((this.homX * other.homZ) == (other.homX * this.homZ)) &&
                    ((this.homY * other.homZ) == (other.homY * this.homZ)))
        }

        override fun hashCode() =
            tryNormalize().hashCode()

        /** whether this is the additive identity (point at infinity). the point at infinity cannot be normalized. */
        val isPointAtInfinity inline get() = this.homZ.isZero()

        /** normalizes this point, converting it to affine coordinates. throws for the point at infinity.
         * @see tryNormalize */
        fun normalize(): Normalized {
            if (this is Normalized) return this
            if (this.isPointAtInfinity) throw IllegalStateException("Cannot normalize point at infinity")
            val zInv = homZ.inverse()
            return Normalized.unsafeFromXY(curve, homX * zInv, homY * zInv)
        }

        /** normalizes this point, converting it to affine coordinates. returns null for the point at infinity.
         * @see normalize */
        @Suppress("NOTHING_TO_INLINE")
        inline fun tryNormalize() = if (!this.isPointAtInfinity) normalize() else null

        companion object {
            private fun requireOnCurve(curve: ShortWeierstrassCurve, x: ModularBigInteger, y: ModularBigInteger) {
                require((x.pow(3) + (curve.a * x) + curve.b) == y.pow(2))
                { "Point (x=${x.toString(16)}, y=${y.toString(16)}) is not on $curve" }
            }

            fun fromXY(curve: ShortWeierstrassCurve, x: ModularBigInteger, y: ModularBigInteger): Normalized {
                require(x.modulus == curve.modulus)
                require(y.modulus == curve.modulus)
                requireOnCurve(curve, x, y)
                return Normalized.unsafeFromXY(curve, x, y)
            }

            fun fromXY(curve: ShortWeierstrassCurve, x: BigInteger, y: BigInteger): Normalized {
                val x = curve.coordinateCreator.fromBigInteger(x)
                val y = curve.coordinateCreator.fromBigInteger(y)
                requireOnCurve(curve, x, y)
                return Normalized.unsafeFromXY(curve, x, y)
            }

            fun fromUncompressed(curve: ShortWeierstrassCurve, x: ByteArray, y: ByteArray): Normalized {
                val x = BigInteger.fromByteArray(x, Sign.POSITIVE)
                val y = BigInteger.fromByteArray(y, Sign.POSITIVE)
                return fromXY(curve, x, y)
            }

            fun fromCompressed(curve: ShortWeierstrassCurve, x: ByteArray, root: Sign): Normalized {
                val x = curve.coordinateCreator.fromByteArray(x)
                val y = decompressY(curve, x, root)
                return Normalized.unsafeFromXY(curve, x, y)
            }

            fun fromCompressed(curve: ShortWeierstrassCurve, x: ByteArray, usePositiveY: Boolean) =
                fromCompressed(curve, x, if (usePositiveY) Sign.POSITIVE else Sign.NEGATIVE)
        }
    }
}

internal object ShortWeierstrassCurveSerializer : KSerializer<ShortWeierstrassCurve> {
    override val descriptor = ECCurveSerializer.descriptor

    override fun serialize(encoder: Encoder, value: ShortWeierstrassCurve) =
        ECCurveSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): ShortWeierstrassCurve =
        ECCurveSerializer.deserialize(decoder) as? ShortWeierstrassCurve
            ?: throw SerializationException("Unknown short-Weierstrass curve")
}
