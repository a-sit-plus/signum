package at.asitplus.signum.indispensable.pki

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

infix fun <T> KmmResult<T>.shouldSucceedWith(b: T) : T =
    (this.getOrThrow() shouldBe b)
class X509ConversionTests : FreeSpec({
    "X509 -> Alg -> X509 is stable" - {
        withData(X509SignatureAlgorithm.entries) {
            it.toX509SignatureAlgorithm() shouldSucceedWith it
            it.algorithm.toX509SignatureAlgorithm() shouldSucceedWith it
        }
    }
})
