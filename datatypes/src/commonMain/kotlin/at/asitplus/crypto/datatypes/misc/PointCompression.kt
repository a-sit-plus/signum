package at.asitplus.crypto.datatypes.misc

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.Signum
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlin.experimental.and
typealias Signum = Boolean


const val ANSI_COMPRESSED_PREFIX_1 = 0x02.toByte()
const val ANSI_COMPRESSED_PREFIX_2 = 0x03.toByte()
const val ANSI_UNCOMPRESSED_PREFIX = 0x04.toByte()

/**
 * Signals which root of the polynomial is used for the y coordinate
 * `SIGNUM_POSITIVE` denotes the first root was selected
 * `SIGNUM_NEGATIVE` denotes the additive inverse
 */
const val SIGNUM_POSITIVE: Signum = true
const val SIGNUM_NEGATIVE: Signum = false
fun Signum.toUInt(): UInt = if (this) 1U else 0U

/**
 * According to https://www.secg.org/sec1-v2.pdf, https://www.secg.org/sec2-v2.pdf
 * all currently supported curves (i.e. secp___r1) are of form F_p with p odd prime and so
 * the compression bit is defined as 2 + (y mod 2) for all curves
 * We assume y is big-endian encoding of valid y coordinate!
 */
fun CryptoPublicKey.Ec.compressY(): Signum = (y.last() and 1.toByte() == 1.toByte())


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
fun decompressY(curve: EcCurve, x: ByteArray, root: Signum): ByteArray {
    val mod4Creator = ModularBigInteger.creatorForModulo(4)
    val xBigMod = curve.modCreator.fromBigInteger(BigInteger.fromByteArray(x, Sign.POSITIVE))
    val alpha = xBigMod.pow(3) + curve.a * xBigMod + curve.b

    require(quadraticResidueTest(alpha))
    val beta = if (mod4Creator.fromBigInteger(curve.modulus) == mod4Creator.fromInt(3))
        alpha.pow((curve.modulus + 1) / 4) else throw IllegalArgumentException("Requires Tonelli-Shanks Algorithm")

    /**
     * Checks mod 2
     */
    return if (beta.residue.bitAt(0) == root) {
        beta.toByteArray()
    } else {
        (curve.modCreator.ZERO - beta).toByteArray()
    }
}

/**
 * Quadratic residue test verifies that a root exists
 * p-1 always even since by assumption p always odd (holds for all implemented curves)
 */
private fun quadraticResidueTest(x: ModularBigInteger): Boolean {
    return x.pow((x.modulus - 1) / 2) == x.getCreator().ONE
}