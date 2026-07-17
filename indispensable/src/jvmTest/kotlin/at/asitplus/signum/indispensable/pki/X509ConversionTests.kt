package at.asitplus.signum.indispensable.pki

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe

infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)

val X509ConversionTests by matrixSuite {
    compact("X509 -> Alg -> X509 is stable") - {
        data(SignatureAlgorithm.entries) test {
            SignatureAlgorithm(it.asn1Representation) shouldBe it
        }
    }
}
