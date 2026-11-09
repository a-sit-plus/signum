package at.asitplus.signum.indispensable.pki
import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.toAsn1
import at.asitplus.signum.indispensable.toAsn1
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe

infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)

val X509ConversionTests by matrixSuite {
    compact("X509 -> Alg -> X509 is stable") - {
        data(EcdsaAlgorithm.entries + RsaAlgorithm.entries) test {
            SignatureAlgorithm.fromAsn1(it.toAsn1()) shouldBe it
        }
    }
}
