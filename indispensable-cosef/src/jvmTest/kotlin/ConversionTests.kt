import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.WithCurveConstraint
import at.asitplus.signum.indispensable.cosef.algorithm.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import kotlin.random.Random

//somehow including kmmresult-test makes this fail
infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)

val ConversionTests by testSuite {
    "COSE -> SigAlg -> COSE is stable" - {

        "All" - {
            withData(at.asitplus.signum.indispensable.cosef.algorithm.CoseAlgorithm.DataIntegrity.entries) {
                it.algorithm.toCoseAlgorithm() shouldSucceedWith it
            }
        }
        "Specialized Signature Algorithms" - {
            withData(at.asitplus.signum.indispensable.cosef.algorithm.CoseAlgorithm.DataIntegrity.entries) {
                it.toCoseAlgorithm() shouldSucceedWith it
            }
        }
    }
    "COSE -> X509 -> COSE" - {
        withData(at.asitplus.signum.indispensable.cosef.algorithm.CoseAlgorithm.Signature.entries) - {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                if ((it.algorithm as? WithCurveConstraint)?.requiredCurve != null) {
                    "Curve information is lost" {
                        val algorithm = x509.toCoseAlgorithm().getOrThrow()
                        algorithm shouldNotBe it
                        algorithm.toString().takeLast(3) shouldBe it.toString().takeLast(3)
                        algorithm.toString().take(2) shouldBe it.toString().take(2)
                    }
                } else "is stable" { x509.toCoseAlgorithm() shouldSucceedWith it }
            }
        }
    }

    "Regression test: COSE key (no keyId) -> CryptoPublicKey -> COSE key (no keyId)" {
        val key = randomPublicKey().toCoseKey().getOrThrow()
        key.keyId shouldBe null
        val cpk = key.toCryptoPublicKey().getOrThrow()
        cpk.toCoseKey().getOrThrow().keyId shouldBe null
        val kid = Random.nextBytes(16)
        cpk.toCoseKey(keyId = kid).getOrThrow().keyId shouldBe kid
    }
}

private fun randomPublicKey() =
    (KeyPairGenerator.getInstance("EC").apply { initialize(256) }
        .genKeyPair().public as ECPublicKey).toCryptoPublicKey().getOrThrow()
