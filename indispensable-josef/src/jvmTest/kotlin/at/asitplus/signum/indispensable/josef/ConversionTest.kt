package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

//somehow including kmmresult-test makes this fail
infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)


val ConversionTest by matrixSuite {
    "JWS -> SigAlg -> JWS is stable" - {
        "All" - {
            data(JwsAlgorithm.entries) test {
                it.algorithm.toJwsAlgorithm() shouldSucceedWith it
            }
        }
        "Specialized SignatureAlgorithm" - {
            data(JwsAlgorithm.entries) test {
                it.toJwsAlgorithm() shouldSucceedWith it
            }
        }
    }
    "JWS -> X509 -> JWS is stable" - {
        data(JwsAlgorithm.Signature.entries) test {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                x509.toJwsAlgorithm() shouldSucceedWith it
            }
        }
    }
    "JWE (symmetric) -> EncryptionAlgorithm -> JWE is stable" - {
        data(JweAlgorithm.Symmetric.entries) test {
            it.algorithm.toJweKwAlgorithm() shouldSucceedWith it
        }
    }
}