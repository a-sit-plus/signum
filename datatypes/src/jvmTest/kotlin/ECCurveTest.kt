import at.asitplus.crypto.datatypes.ECCurve
import com.ionspin.kotlin.bignum.integer.toBigInteger
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe


/**
 * Verifies the hard coded field modulus versus its functional definition
 * See https://www.secg.org/sec2-v2.pdf chapter 2
 */
class ECCurveTest: FreeSpec({
    "SECP256 modulus correct" {
        ECCurve.SECP_256_R_1.modulus shouldBe
                (2.toBigInteger().shl(223)
                        * (2.toBigInteger().shl(31) - 1.toBigInteger())
                        + 2.toBigInteger().shl(191)
                        + 2.toBigInteger().shl(95)
                        - 1.toBigInteger())
    }

    "SECP384 modulus correct" {
        ECCurve.SECP_384_R_1.modulus shouldBe
                (2.toBigInteger().shl(383)
                        - 2.toBigInteger().shl(127)
                        - 2.toBigInteger().shl(95)
                        + 2.toBigInteger().shl(31)
                        - 1.toBigInteger())
    }

    "SECP521 modulus correct" {
        ECCurve.SECP_521_R_1.modulus shouldBe
                (2.toBigInteger().shl(520)
                        - 1.toBigInteger())
    }

    "Calculated parameters test" {
        ECCurve.SECP_256_R_1.keyLengthBits shouldBe 256u
        ECCurve.SECP_384_R_1.keyLengthBits shouldBe 384u
        ECCurve.SECP_521_R_1.keyLengthBits shouldBe 521u

        ECCurve.SECP_256_R_1.signatureLengthBytes shouldBe 64u
        ECCurve.SECP_384_R_1.signatureLengthBytes shouldBe 96u
        ECCurve.SECP_521_R_1.signatureLengthBytes shouldBe 132u

        ECCurve.SECP_256_R_1.coordinateLengthBytes shouldBe 32u
        ECCurve.SECP_384_R_1.coordinateLengthBytes shouldBe 48u
        ECCurve.SECP_521_R_1.coordinateLengthBytes shouldBe 66u
    }
})
