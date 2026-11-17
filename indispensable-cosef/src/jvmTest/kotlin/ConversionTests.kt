import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import kotlin.random.Random

val ConversionTests by matrixSuite {
    "COSE -> SigAlg -> COSE is stable" - {

        "All" - {
            data(CoseAlgorithm.Signature.entries) test {
                it.algorithm.toCoseAlgorithm() shouldBe it
            }
            data(CoseAlgorithm.MAC.entries) test {
                it.algorithm.toCoseAlgorithm() shouldBe it
            }
        }
        "Specialized Signature Algorithms" - {
            data(CoseAlgorithm.Signature.entries) test {
                it.toCoseAlgorithm() shouldBe it
            }
            data(CoseAlgorithm.MAC.entries) test {
                it.toCoseAlgorithm() shouldBe it
            }
        }
    }
    "COSE -> SigAlg -> COSE" - {
        data(CoseAlgorithm.Signature.entries) - {
            it.algorithm.asn1.toRepresentation().let { x509 ->
                if (it.algorithm is EcdsaAlgorithm && (it.algorithm as EcdsaAlgorithm).requiredCurve != null) {
                    "Curve information is lost" {
                        val algorithm = SignatureAlgorithm.fromAsn1(x509).toCoseAlgorithm()
                        algorithm shouldNotBe it
                        algorithm.toString().takeLast(3) shouldBe it.toString().takeLast(3)
                        algorithm.toString().take(2) shouldBe it.toString().take(2)
                    }
                } else {
                    "is stable" {
                        SignatureAlgorithm.fromAsn1(x509).toCoseAlgorithm() shouldBe it
                    }
                }
            }
        }
    }

    "Regression test: COSE key (no keyId) -> CryptoPublicKey -> COSE key (no keyId)" {
        val key = randomPublicKey().toCoseKey()
        key.keyId shouldBe null
        val cpk = key.toCryptoPublicKey()
        cpk.toCoseKey().keyId shouldBe null
        val kid = Random.nextBytes(16)
        cpk.toCoseKey(keyId = kid).keyId shouldBe kid
    }
}

private fun randomPublicKey() =
    (KeyPairGenerator.getInstance("EC").apply { initialize(256) }
        .genKeyPair().public as ECPublicKey).toCryptoPublicKey()
