package at.asitplus.signum.indispensable.josef
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe

val ConversionTest by matrixSuite {
    "JWS -> SigAlg -> JWS is stable" - {
        "All" - {
            data(JwsAlgorithm.Signature.entries) test {
                it.algorithm.toJwsAlgorithm() shouldBe it
            }
            data(JwsAlgorithm.MAC.entries) test {
                it.algorithm.toJwsAlgorithm() shouldBe it
            }
        }
        "Specialized SignatureAlgorithm" - {
            data(JwsAlgorithm.Signature.entries) test {
                it.toJwsAlgorithm() shouldBe it
            }
            data(JwsAlgorithm.MAC.entries) test {
                it.toJwsAlgorithm() shouldBe it
            }
        }
    }
    "JWS -> X509 -> JWS is stable" - {
        data(JwsAlgorithm.Signature.entries) test {
            it.algorithm.asn1.toRepresentation().let { x509 ->
                SignatureAlgorithm.fromAsn1(x509).toJwsAlgorithm() shouldBe it
            }
        }
    }
    "JWE (symmetric) -> EncryptionAlgorithm -> JWE is stable" - {
        data(JweAlgorithm.Symmetric.entries) test {
            it.algorithm.toJweKwAlgorithm() shouldBe it
        }
    }
}