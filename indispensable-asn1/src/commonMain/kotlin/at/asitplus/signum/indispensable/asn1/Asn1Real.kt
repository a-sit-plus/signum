package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.encoding.toTwosComplementByteArray
import at.asitplus.signum.indispensable.asn1.encoding.toUnsignedByteArray
import kotlin.math.sign


private const val IEEE754_BIAS = 1023

/**
 * ASN.1 REAL number. Mind possible loss of precision compared to Kotlin's built-in types.
 * This type is irrelevant for PKI applications, but required for generic ASN.1 serialization
 */
sealed class Asn1Real : Asn1Encodable<Asn1Primitive> {

    object Zero : Asn1Real()
    object PositiveInfinity : Asn1Real()
    object NegativeInfinity : Asn1Real()

    data class Finite(val sign: Asn1Integer.Sign, val normalizedMantissa: ULong, val normalizedExponent: Long) :
        Asn1Real()

    override fun encodeToTlv(): Asn1Primitive =
        when (this) {
            PositiveInfinity -> Asn1Primitive(Asn1Element.Tag.REAL, byteArrayOf(0x40))
            NegativeInfinity -> Asn1Primitive(Asn1Element.Tag.REAL, byteArrayOf(0x41))
            Zero -> Asn1Primitive(Asn1Element.Tag.REAL, byteArrayOf())
            is Finite -> {
                val exponentOctets = normalizedExponent.toTwosComplementByteArray()
                val mantissaOctets = normalizedMantissa.toTwosComplementByteArray()
                val exponentLengthEncoding = when (exponentOctets.size) {
                    1 -> 0
                    2 -> 1
                    3 -> 2
                    else -> 3 //this will never exceed 255 bytes, because Long spans 8 bytes at most
                }

                val signEncoding = if (sign == Asn1Integer.Sign.NEGATIVE) 1 shl 6 else 0
                val binaryEncoding = 1 shl 7

                val exponentLengthOctets =
                    if (exponentLengthEncoding == 3) exponentOctets.size.toUnsignedByteArray() else byteArrayOf()

                Asn1Primitive(
                    Asn1Element.Tag.REAL, byteArrayOf(
                        (binaryEncoding or signEncoding or exponentLengthEncoding).toByte(),
                        *exponentLengthOctets,
                        *exponentOctets,
                        *mantissaOctets
                    )
                )
            }
        }

    companion object {
        operator fun invoke(number: Double): KmmResult<Asn1Real> = catching {
            when (number) {
                Double.NaN -> throw IllegalArgumentException("NaN cannot be encoded into ASN.1")
                -0.0, 0.0 -> Zero
                Double.NEGATIVE_INFINITY -> NegativeInfinity
                Double.POSITIVE_INFINITY -> PositiveInfinity
                else -> number.getAsn1RealComponents()
                    ?.let { (sign, exponent, mantissa) -> Finite(sign, mantissa, exponent) } ?: Zero
            }
        }

        private fun Double.getAsn1RealComponents(): Triple<Asn1Integer.Sign, Long, ULong>? {
            val bits = this.toBits()
            val rawExponent = ((bits ushr 52) and 0x7FF).toInt() // 11 bits
            val rawMantissa = (bits and 0xFFFFFFFFFFFFF).toULong()// 52 bits

            val exponent = rawExponent - IEEE754_BIAS - 52
            // Normal: rawExponent != 0 => implicit leading 1
            val mantissa = if (rawExponent != 0) (1uL shl 52) or rawMantissa else rawMantissa

            if (mantissa == 0uL) {
                // If we end up with no bits in the mantissa => effectively 0.0
                // Could happen if fraction=0 for subnormal
                return null
            }
            var normalizedExponent = exponent
            var normalizedMantissa = mantissa
            while (normalizedMantissa % 2u == 0uL) {
                normalizedMantissa = normalizedMantissa shr 1
                normalizedExponent++
            }
            return Triple(
                if (sign == 1.0) Asn1Integer.Sign.POSITIVE else Asn1Integer.Sign.NEGATIVE,
                normalizedExponent.toLong(),
                normalizedMantissa
            )
        }
    }
}