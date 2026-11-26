package at.asitplus.signum.indispensable

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.matchers.shouldBe

val JcaCurveMappingTest by matrixSuite {
    "A JCA mapping provider can resolve a curve with its own model" {
        isolatedScenario(JcaCurveMappingScenarios::class.java, "resolveCurve")
    }
}

internal object JcaCurveMappingScenarios {
    @JvmStatic
    fun resolveCurve() {
        val nist = ECCurve.SECP_256_R_1
        ECCurve.byJcaName(nist.jcaName) shouldBe nist

        Signum.installIndispensable()
        val curve = object : ECCurve {
            override val name = "test-montgomery"
            override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.4")
            override val order = BigInteger.fromInt(5)
            override val cofactor = 4
        }
        ServiceLoader.register<JcaMappingProvider>(object : JcaMappingProvider {
            override fun curveForJcaName(name: String): ECCurve? =
                curve.takeIf { name == it.name }
        })

        ECCurve.byJcaName(curve.name) shouldBe curve
        ECCurve.byJcaName(nist.jcaName) shouldBe nist
        ECCurve.byJcaName("unknown-curve") shouldBe null
        EcdsaPublicKey(nist.generator, false).toJcaPublicKey().toPublicKey().curve shouldBe nist
    }
}
