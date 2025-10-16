import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import kotlin.random.Random
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

//somehow including kmmresult-test makes this fail
infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)

val ConversionTests by testSuite() {
    "COSE -> SigAlg -> COSE is stable" - {

        "All" - {
            withData(CoseAlgorithm.DataIntegrity.entries) {
                it.algorithm.toCoseAlgorithm() shouldSucceedWith it
            }
        }
        "Specialized Signature Algorithms" - {
            withData(CoseAlgorithm.DataIntegrity.entries) {
                it.toCoseAlgorithm() shouldSucceedWith it
            }
        }
    }
    "COSE -> X509 -> COSE is stable" - {
        withData(CoseAlgorithm.Signature.entries) {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                x509.toCoseAlgorithm() shouldSucceedWith it
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
