package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope
import at.asitplus.signum.indispensable.SpecializedDataIntegrityAlgorithm
import at.asitplus.signum.indispensable.josef.algorithm.toJweKwAlgorithm
import at.asitplus.signum.indispensable.josef.algorithm.toJwsAlgorithm

//somehow including kmmresult-test makes this fail
infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)


val ConversionTest by testSuite {
    "JWS -> SigAlg -> JWS is stable" - {
        "All" - {
            withData(at.asitplus.signum.indispensable.josef.algorithm.JwsAlgorithm.entries.filterIsInstance<SpecializedDataIntegrityAlgorithm>()) {
                it.algorithm.toJwsAlgorithm() shouldSucceedWith it
            }
        }
        "Specialized SignatureAlgorithm" - {
            withData(at.asitplus.signum.indispensable.josef.algorithm.JwsAlgorithm.entries.filterIsInstance<SpecializedDataIntegrityAlgorithm>()) {
                it.toJwsAlgorithm() shouldSucceedWith it
            }
        }
    }
    "JWS -> X509 -> JWS is stable" - {
        withData(at.asitplus.signum.indispensable.josef.algorithm.JwsAlgorithm.Signature.entries) {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                x509.toJwsAlgorithm() shouldSucceedWith it
            }
        }
    }
    "JWE (symmetric) -> EncryptionAlgorithm -> JWE is stable" - {
        withData(at.asitplus.signum.indispensable.josef.algorithm.JweAlgorithm.Symmetric.entries) {
            it.algorithm.toJweKwAlgorithm() shouldSucceedWith it
        }
    }
}
