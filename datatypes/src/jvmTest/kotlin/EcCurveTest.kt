import at.asitplus.crypto.datatypes.EcCurve
import com.ionspin.kotlin.bignum.integer.toBigInteger
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class EcCurveTest: FreeSpec({
    "SECP256 modulus correct" {
        EcCurve.SECP_256_R_1.modulus shouldBe
                (2.toBigInteger().shl(223)
                        * (2.toBigInteger().shl(31) - 1.toBigInteger())
                        + 2.toBigInteger().shl(191)
                        + 2.toBigInteger().shl(95)
                        - 1.toBigInteger())
    }

    "SECP384 modulus correct" {
        EcCurve.SECP_384_R_1.modulus shouldBe
                (2.toBigInteger().shl(383)
                        - 2.toBigInteger().shl(127)
                        - 2.toBigInteger().shl(95)
                        + 2.toBigInteger().shl(31)
                        - 1.toBigInteger())
    }

    "SECP521 modulus correct" {
        EcCurve.SECP_521_R_1.modulus shouldBe
                (2.toBigInteger().shl(520)
                        - 1.toBigInteger())
    }

})