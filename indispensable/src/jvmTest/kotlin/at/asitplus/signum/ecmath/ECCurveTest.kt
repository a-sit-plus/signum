package at.asitplus.signum.ecmath

import at.asitplus.signum.indispensable.ECCurve
import com.ionspin.kotlin.bignum.integer.toBigInteger
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

/**
 * Verifies the hard coded field modulus versus its functional definition
 * See https://www.secg.org/sec2-v2.pdf chapter 2
 */
val ECCurveTest  by testSuite() {
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
        ECCurve.SECP_256_R_1.scalarLength.bits shouldBe 256u
        ECCurve.SECP_384_R_1.scalarLength.bits shouldBe 384u
        ECCurve.SECP_521_R_1.scalarLength.bits shouldBe 521u

        ECCurve.SECP_256_R_1.scalarLength.bytes * 2u shouldBe 64u
        ECCurve.SECP_384_R_1.scalarLength.bytes * 2u shouldBe 96u
        ECCurve.SECP_521_R_1.scalarLength.bytes * 2u shouldBe 132u

        ECCurve.SECP_256_R_1.coordinateLength.bytes shouldBe 32u
        ECCurve.SECP_384_R_1.coordinateLength.bytes shouldBe 48u
        ECCurve.SECP_521_R_1.coordinateLength.bytes shouldBe 66u
    }
}
