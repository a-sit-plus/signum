package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.test.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

//somehow including kmmresult-test makes this fail
infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)


class ConversionTest : FreeSpec({
    "JWS -> SigAlg -> JWS is stable" - {
        "All" - {
            withData(JwsAlgorithm.entries) {
                it.algorithm.toJwsAlgorithm() shouldSucceedWith it
            }
        }
        "Specialized SignatureAlgorithm" - {
            withData(JwsAlgorithm.entries) {
                it.toJwsAlgorithm() shouldSucceedWith it
            }
        }
    }
    "JWS -> X509 -> JWS is stable" - {
        withData(JwsAlgorithm.Signature.entries) {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                x509.toJwsAlgorithm() shouldSucceedWith it
            }
        }
    }
    "JWE (symmetric) -> EncryptionAlgorithm -> JWE is stable" - {
        withData(JweAlgorithm.Symmetric.entries) {
            it.algorithm.toJweKwAlgorithm() shouldSucceedWith it
        }
    }
})