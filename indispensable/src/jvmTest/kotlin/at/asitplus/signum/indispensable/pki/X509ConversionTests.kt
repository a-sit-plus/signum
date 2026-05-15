package at.asitplus.signum.indispensable.pki

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)

val X509ConversionTests by testSuite {
    "X509 -> Alg -> X509 is stable" - {
        withData(SignatureAlgorithm.entries) {
            SignatureAlgorithm(it.asn1Representation) shouldBe it
        }
    }
}
