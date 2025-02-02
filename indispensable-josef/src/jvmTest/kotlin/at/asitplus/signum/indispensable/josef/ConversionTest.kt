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
        withData(JwsAlgorithm.entries) {
            it.toJwsAlgorithm() shouldSucceedWith it
            it.algorithm.toJwsAlgorithm() shouldSucceedWith it
        }
    }
    "JWS -> X509 -> JWS is stable" - {
        withData(JwsAlgorithm.signatureAlgorithms) {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                x509.toJwsAlgorithm() shouldSucceedWith it
            }
        }
    }
})