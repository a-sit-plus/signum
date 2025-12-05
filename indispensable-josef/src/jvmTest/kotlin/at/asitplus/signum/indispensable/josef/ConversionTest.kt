package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

//somehow including kmmresult-test makes this fail
infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)


val ConversionTest by testSuite {
    "JWS -> SigAlg -> JWS is stable" - {
        "All" - {
            withData(JwsAlgorithm.entries) {
                it.algorithm.toJwsAlgorithm(lenient = false) shouldSucceedWith it
            }
        }
        "Specialized SignatureAlgorithm" - {
            withData(JwsAlgorithm.entries) {
                it.toJwsAlgorithm(lenient = false) shouldSucceedWith it
            }
        }
    }
    "JWS -> X509 -> JWS is stable" - {
        withData(JwsAlgorithm.Signature.entries) {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                x509.toJwsAlgorithm(lenient = true) shouldSucceedWith it
            }
        }
    }
    "JWE (symmetric) -> EncryptionAlgorithm -> JWE is stable" - {
        withData(JweAlgorithm.Symmetric.entries) {
            it.algorithm.toJweKwAlgorithm() shouldSucceedWith it
        }
    }
}