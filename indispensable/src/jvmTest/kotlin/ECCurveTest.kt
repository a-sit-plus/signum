import at.asitplus.signum.indispensable.*
import com.ionspin.kotlin.bignum.integer.toBigInteger
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.util.Stack
import kotlin.reflect.KClass


/**
 * Verifies the hard coded field modulus versus its functional definition
 * See https://www.secg.org/sec2-v2.pdf chapter 2
 */
class ECCurveTest : FreeSpec({
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

    "EC interface entries completeness" - {
        val discovered = mutableSetOf<NewECCurve>()
        val queue = Stack<KClass<out NewECCurve>>()
        queue.push(NewECCurve::class)
        while (!queue.empty()) {
            queue.pop().sealedSubclasses.shouldNotBeNull().forEach {
                when (val o = it.objectInstance) {
                    null -> queue.push(it)
                    else -> discovered.add(o)
                }
            }
        }
        NewECCurve.entries.toSet() shouldBe discovered
    }

    "EC parameter relationships" - {
        withData(NewECCurve.entries) { curve ->
            curve.modulus * curve.extensionDegree shouldBe curve.fieldOrder
            curve.order * curve.cofactor shouldBe curve.n
            if (curve is WeierstrassCurve) {
                val (x, y) = curve.generator
                // weierstrass form curve equation: y² = x³+ax+b
                x.pow(3) + (curve.a * x) + curve.b shouldBe y.pow(2)
            }
        }
    }
})
