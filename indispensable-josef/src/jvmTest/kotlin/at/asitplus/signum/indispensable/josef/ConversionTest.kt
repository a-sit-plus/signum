package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

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
            withData(JwsAlgorithm.Signature.entries) {
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
})