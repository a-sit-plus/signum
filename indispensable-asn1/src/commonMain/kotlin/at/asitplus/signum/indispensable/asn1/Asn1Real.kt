package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
import kotlin.math.pow
import kotlin.math.sign


private const val IEEE754_BIAS = 1023

/**
 * ASN.1 REAL number. Mind possible loss of precision compared to Kotlin's built-in types.
 * This type is irrelevant for PKI applications, but required for generic ASN.1 serialization
 */
sealed interface Asn1Real : Asn1Encodable<Asn1Primitive> {

    /**
     * Converts this Asn1Real to a [Float]. **Beware of *probable* loss of precision!**
     */
    fun toFloat() = toDouble().toFloat()

    /**
     * Converts this Asn1Real to a [Double]. **Beware of possible loss of precision!**
     */
    fun toDouble() = when (this) {
        is Finite -> (normalizedMantissa.toString().toDouble() * 2.0.pow(normalizedExponent.toDouble()))
        NegativeInfinity -> Double.NEGATIVE_INFINITY
        PositiveInfinity -> Double.POSITIVE_INFINITY
        Zero -> 0.0
    }

    object Zero : Asn1Real
    object PositiveInfinity : Asn1Real
    object NegativeInfinity : Asn1Real

    data class Finite internal constructor(val normalizedMantissa: Asn1Integer, val normalizedExponent: Long) :
        Asn1Real

    override fun encodeToTlv(): Asn1Primitive = encodeToAsn1Primitive()

    /** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 REAL */
    fun encodeToAsn1ContentBytes(): ByteArray = when (this) {
        PositiveInfinity -> byteArrayOf(0x40)
        NegativeInfinity -> byteArrayOf(0x41)
        Zero -> byteArrayOf()
        is Finite -> {
            val exponentOctets = normalizedExponent.toTwosComplementByteArray()
            val mantissaOctets = normalizedMantissa.magnitude.let {
                if (it.first().countLeadingZeroBits() == 0) byteArrayOf(0, *it)
                else it
            }
            val (exponentLengthEncoding, exponentLengthOctets) = when (exponentOctets.size) {
                1 -> 0 to byteArrayOf()
                2 -> 1 to byteArrayOf()
                3 -> 2 to byteArrayOf()
                else -> 3 to exponentOctets.size.toUnsignedByteArray() //this will never exceed 255 bytes, because Long spans 8 bytes at most
            }

            val signEncoding = if (normalizedMantissa.sign == Asn1Integer.Sign.NEGATIVE) 0x40 else 0
            val binaryEncoding = 0x80

            byteArrayOf(
                (binaryEncoding or signEncoding or exponentLengthEncoding).toByte(),
                *exponentLengthOctets,
                *exponentOctets,
                *mantissaOctets
            )
        }
    }

    companion object : Asn1Decodable<Asn1Primitive, Asn1Real> {
        /**
         * Converts a Double into an ASN.1 REAL.
         * **Beware of the fact that ASN.1 REAL zero knows no sign!**
         *
         * @throws Asn1Exception when passing [Double.NaN]
         */
        @Throws(Asn1Exception::class)
        operator fun invoke(number: Double): Asn1Real = runRethrowing {
            when (number) {
                Double.NaN -> throw IllegalArgumentException("NaN cannot be encoded into ASN.1")
                -0.0, 0.0 -> Zero
                Double.NEGATIVE_INFINITY -> NegativeInfinity
                Double.POSITIVE_INFINITY -> PositiveInfinity
                else -> number.getAsn1RealComponents()
                    ?.let { (exponent, mantissa) -> Finite(mantissa, exponent) } ?: Zero
            }
        }

        /**
         * Converts a Float into an ASN.1 REAL.
         *
         * @throws Asn1Exception when passing [Float.NaN]
         */
        @Throws(Asn1Exception::class)
        @Suppress("NOTHING_TO_INLINE")
        inline operator fun invoke(number: Float): Asn1Real = invoke(number.toDouble())

        private fun Double.getAsn1RealComponents(): Pair<Long, Asn1Integer>? {
            val bits = this.toBits()
            val rawExponent = ((bits ushr 52) and 0x7FF).toInt() // 11 bits
            val rawMantissa = (bits and 0xFFFFFFFFFFFFF)// 52 bits

            val exponent = rawExponent - IEEE754_BIAS - 52
            // Normal: rawExponent != 0 => implicit leading 1
            val mantissa = if (rawExponent != 0) (1L shl 52) or rawMantissa else rawMantissa

            if (mantissa == 0L) {
                // If we end up with no bits in the mantissa => effectively 0.0
                // Could happen if fraction=0 for subnormal
                return null
            }
            var normalizedExponent = exponent
            var normalizedMantissa = mantissa
            normalizedMantissa.countTrailingZeroBits().let { bits ->
                normalizedMantissa = normalizedMantissa shr bits
                normalizedExponent += bits
            }

            return normalizedExponent.toLong() to
                    if (this.sign == 1.0) Asn1Integer.Positive(VarUInt(normalizedMantissa.toUnsignedByteArray()))
                    else Asn1Integer.Negative(VarUInt(normalizedMantissa.toUnsignedByteArray()))
        }

        /**
         * Decodes a [Asn1Real] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 REAL
         */
        @Throws(Asn1Exception::class)
        fun decodeFromAsn1ContentBytes(bytes: ByteArray): Asn1Real = runRethrowing {
            if (bytes.isEmpty()) return Asn1Real.Zero

            val identifierOctet = bytes.first().toInt()
            when (identifierOctet) {
                0x40 -> Asn1Real.PositiveInfinity
                0x41 -> Asn1Real.NegativeInfinity
                else -> {
                    require(identifierOctet < 0) { "ASN.1 REAL is not binary encoded" }
                    val sign =
                        if (0x40 and identifierOctet == 0) Asn1Integer.Sign.POSITIVE else Asn1Integer.Sign.NEGATIVE
                    val exponentLength = when (identifierOctet and 0b11) {
                        0 -> 1
                        1 -> 2
                        2 -> 3
                        else -> null
                    }

                    val exponent = when (exponentLength) {
                        1 -> bytes[1].toLong()
                        2 -> Long.fromTwosComplementByteArray(bytes.sliceArray(1..2))
                        3 -> Long.fromTwosComplementByteArray(bytes.sliceArray(1..3))
                        else -> Long.fromTwosComplementByteArray(
                            bytes.sliceArray(
                                2..Int.fromTwosComplementByteArray(
                                    byteArrayOf(0, bytes[1])
                                )
                            )
                        )
                    }
                    val mantissaOffset = when (exponentLength) {
                        1 -> 2
                        2 -> 3
                        3 -> 4
                        else -> 2 + Int.fromTwosComplementByteArray(byteArrayOf(0, bytes[1]))
                    }

                    val mantissa = VarUInt(bytes.sliceArray(mantissaOffset..<bytes.size))
                    if (sign == Asn1Integer.Sign.POSITIVE) Asn1Real.Finite(Asn1Integer.Positive(mantissa), exponent)
                    else Asn1Real.Finite(Asn1Integer.Negative(mantissa), exponent)
                }
            }
        }

        override fun doDecode(src: Asn1Primitive): Asn1Real = src.decodeToAsn1Real()
    }
}