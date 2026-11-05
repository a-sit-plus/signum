package at.asitplus.signum.indispensable

import at.asitplus.catchingAs
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.indispensable.misc.compressY
import at.asitplus.signum.indispensable.misc.decompressY
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import com.ionspin.kotlin.bignum.BigNumber
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.jvm.JvmSynthetic

private fun BigNumber.Creator<ModularBigInteger>.fromByteArray(v: ByteArray) =
    fromBigInteger(BigInteger.fromByteArray(v, Sign.POSITIVE))

/**
 * elliptic curve point in homogeneous coordinates (X,Y,Z)
 * to access affine coordinates, normalize the point. the point at infinity cannot be normalized.
 * @see normalize
 * @see tryNormalize
 */
sealed class ECPoint private constructor(
    /** the curve on which this point lies */
    val curve: ECCurve,
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
) {

    class General private constructor(
        c: ECCurve, hX: ModularBigInteger, hY: ModularBigInteger, hZ: ModularBigInteger
    ) : ECPoint(c, hX, hY, hZ) {
        companion object {
            @PublishedApi
            @JvmSynthetic
            internal fun unsafeFromXYZ(c: ECCurve, x: ModularBigInteger, y: ModularBigInteger, z: ModularBigInteger) =
                General(c, x, y, z)
        }
    }

    /** normalized elliptic curve point (Z = 1). cannot be the point at infinity. */
    @Serializable(with = ECPointSerializer::class)
    class Normalized private constructor(
        curve: ECCurve,
        x: ModularBigInteger,
        y: ModularBigInteger
    ) : ECPoint(curve, x, y, curve.coordinateCreator.ONE) {
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
            internal fun unsafeFromXY(curve: ECCurve, x: ModularBigInteger, y: ModularBigInteger) =
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
        if (other !is ECPoint) return false
        if (this.curve != other.curve) return false
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
        private fun requireOnCurve(curve: ECCurve, x: ModularBigInteger, y: ModularBigInteger) {
            require((x.pow(3) + (curve.a * x) + curve.b) == y.pow(2))
            { "Point (x=${x.toString(16)}, y=${y.toString(16)}) is not on $curve" }
        }

        fun fromXY(curve: ECCurve, x: ModularBigInteger, y: ModularBigInteger): Normalized {
            require(x.modulus == curve.modulus)
            require(y.modulus == curve.modulus)
            requireOnCurve(curve, x, y)
            return Normalized.unsafeFromXY(curve, x, y)
        }

        fun fromXY(curve: ECCurve, x: BigInteger, y: BigInteger): Normalized {
            val x = curve.coordinateCreator.fromBigInteger(x)
            val y = curve.coordinateCreator.fromBigInteger(y)
            requireOnCurve(curve, x, y)
            return Normalized.unsafeFromXY(curve, x, y)
        }

        fun fromUncompressed(curve: ECCurve, x: ByteArray, y: ByteArray): Normalized {
            val x = BigInteger.fromByteArray(x, Sign.POSITIVE)
            val y = BigInteger.fromByteArray(y, Sign.POSITIVE)
            return fromXY(curve, x, y)
        }

        fun fromCompressed(curve: ECCurve, x: ByteArray, root: Sign): Normalized {
            val x = curve.coordinateCreator.fromByteArray(x)
            val y = decompressY(curve, x, root)
            return Normalized.unsafeFromXY(curve, x, y)
        }

        fun fromCompressed(curve: ECCurve, x: ByteArray, usePositiveY: Boolean) =
            fromCompressed(curve, x, if (usePositiveY) Sign.POSITIVE else Sign.NEGATIVE)
    }
}

/**
 * Serializes a point as a byte array holding the DER encoding of its [EcdsaPublicKey]: a SubjectPublicKeyInfo
 * (RFC 5480), which names the curve. The point is written uncompressed, but compressed points are also decoded.
 *
 * Decoding fails with a [SerializationException] if the bytes are not an EC public key on a supported curve.
 */
object ECPointSerializer : KSerializer<ECPoint.Normalized> {
    override val descriptor: SerialDescriptor =
        SerialDescriptor("ECPoint", ByteArraySerializer().descriptor)

    override fun serialize(encoder: Encoder, value: ECPoint.Normalized) =
        encoder.encodeSerializableValue(ByteArraySerializer(), value.asPublicKey().encodeToDer())

    override fun deserialize(decoder: Decoder): ECPoint.Normalized {
        val der = decoder.decodeSerializableValue(ByteArraySerializer())
        return catchingAs({ SerializationException("Not the encoding of an EC point: ${it.message}", it) }) {
            val key = CryptoPublicKey.decodeFromDer(der)
            require(key is EcdsaPublicKey) { "Expected an EC public key, got ${key::class.simpleName}" }
            key.publicPoint
        }.getOrThrow()
    }
}
