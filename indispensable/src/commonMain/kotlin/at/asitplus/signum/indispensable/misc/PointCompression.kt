package at.asitplus.signum.indispensable.misc

import at.asitplus.signum.indispensable.ECCurve
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger

enum class ANSIECPrefix(val prefixByte: Byte) {
    COMPRESSED_MINUS(0x02),
    COMPRESSED_PLUS(0x03),
    UNCOMPRESSED(0x04);

    val isUncompressed inline get() = (this == UNCOMPRESSED)
    val isCompressed inline get() = !isUncompressed
    val compressionSign
        inline get() = when (this) {
            COMPRESSED_MINUS -> Sign.NEGATIVE
            COMPRESSED_PLUS -> Sign.POSITIVE
            UNCOMPRESSED -> throw IllegalStateException("not compressed")
        }
    val prefixUByte inline get() = prefixByte.toUByte()

    @Suppress("NOTHING_TO_INLINE")
    inline operator fun plus(that: ByteArray) = byteArrayOf(prefixByte, *that)

    companion object {

        /**
         * Gets the [ANSIECPrefix] for [byte].
         * @throws IllegalArgumentException for bytes that don't map to a valid prefix
         */
        @Suppress("NOTHING_TO_INLINE")
        inline fun fromPrefixByte(byte: Byte) = when (byte) {
            COMPRESSED_MINUS.prefixByte -> COMPRESSED_MINUS
            COMPRESSED_PLUS.prefixByte -> COMPRESSED_PLUS
            UNCOMPRESSED.prefixByte -> UNCOMPRESSED
            else -> throw IllegalArgumentException("invalid prefix $byte")
        }

        /**
         * Gets the [ANSIECPrefix] for [sign].
         * @throws IllegalArgumentException for [Sign.ZERO]
         */
        @Suppress("NOTHING_TO_INLINE")
        inline fun forSign(sign: Sign) = when (sign) {
            Sign.NEGATIVE -> COMPRESSED_MINUS
            Sign.POSITIVE -> COMPRESSED_PLUS
            Sign.ZERO -> throw IllegalArgumentException("Sign.ZERO")
        }

        @Suppress("NOTHING_TO_INLINE")
        inline fun ByteArray.hasPrefix(prefix: ANSIECPrefix) = (first() == prefix.prefixByte)
    }
}

/**
 * According to https://www.secg.org/sec1-v2.pdf, https://www.secg.org/sec2-v2.pdf
 * all currently supported curves (i.e. secp___r1) are of form F_p with p odd prime and so
 * the compression bit is defined as 2 + (y mod 2) for all curves
 * We assume y is big-endian encoding of valid y coordinate!
 */
internal fun compressY(curve: ECCurve, x: ModularBigInteger, y: ModularBigInteger): Sign =
    if (y.residue.bitAt(0)) Sign.POSITIVE else Sign.NEGATIVE


/**
 * Tries to decompress the specified root given a bytearray and curve. Can fail on invalid input.
 * For the currently supported curves it holds that p = 3 (mod 4), where p denotes the modulus.
 * This property allows the closed formula solution
 * x^2 = a (mod p) <=> x = b^((p+1)/4) && a is quadratic residue
 *
 * @param curve can only be one of the currently supported curves
 * @param x not necessarily valid bytearray encoding of x-coordinate on given curve
 * @param root is used to determine which y-coordinate to take

 *
 * @throws IllegalArgumentException if curve gets added that violates our current assumptions
 * @throws IllegalArgumentException if x does not permit a square root, i.e. is not a valid encoding
 */
@Throws(Throwable::class)
internal fun decompressY(curve: ECCurve, x: ModularBigInteger, sign: Sign): ModularBigInteger {
    require(sign != Sign.ZERO)
    val alpha = x.pow(3) + curve.a * x + curve.b

    require(quadraticResidueTest(alpha))
        { "Invalid compressed point (x=$x) on $curve" }
    require(curve.modulus.bitAt(0) && curve.modulus.bitAt(1)) // (modulus % 4) == 3
        { "Decompression on $curve requires Tonelli-Shanks Algorithm" }


    val beta = alpha.pow((curve.modulus + 1) / 4)

    /**
     * Checks mod 2
     */
    return if (beta.residue.bitAt(0) == (sign == Sign.POSITIVE)) {
        beta
    } else {
        (curve.coordinateCreator.ZERO - beta)
    }
}

/**
 * Quadratic residue test verifies that a root exists
 * p-1 always even since by assumption p always odd (holds for all implemented curves)
 */
private fun quadraticResidueTest(x: ModularBigInteger): Boolean {
    return x.pow((x.modulus - 1) / 2) == x.getCreator().ONE
}
