package at.asitplus.signum.indispensable

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val JcaCurveMappingTest by matrixSuite {
    "A JCA mapping provider can map a curve with its own model in both directions" {
        isolatedScenario(JcaCurveMappingScenarios::class.java, "resolveCurve")
    }
}

internal object JcaCurveMappingScenarios {
    @JvmStatic
    fun resolveCurve() {
        val nist = ECCurve.SECP_256_R_1
        nist.jcaName shouldBe "secp256r1"
        ECCurve.byJcaName("secp256r1") shouldBe nist

        Signum.installIndispensable()
        val customCurve = object : ECCurve {
            override val name = "test-montgomery"
            override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.4")
            override val order = BigInteger.fromInt(5)
            override val cofactor = 4
        }
        val jcaAlias = "TestMontgomery"
        shouldThrow<UnsupportedCryptoException> { customCurve.jcaName }
        ServiceLoader.register<JcaMappingProvider>(object : JcaMappingProvider {
            override fun curveForJcaName(name: String): ECCurve? =
                customCurve.takeIf { name == jcaAlias }

            override fun jcaNameForCurve(curve: ECCurve): String? =
                jcaAlias.takeIf { curve === customCurve }
        })

        customCurve.jcaName shouldBe jcaAlias
        ECCurve.byJcaName(jcaAlias) shouldBe customCurve
        nist.jcaName shouldBe "secp256r1"
        ECCurve.byJcaName(nist.jcaName) shouldBe nist
        ECCurve.byJcaName("unknown-curve") shouldBe null
        EcdsaPublicKey(nist.generator, false).toJcaPublicKey().toPublicKey().curve shouldBe nist
    }
}
