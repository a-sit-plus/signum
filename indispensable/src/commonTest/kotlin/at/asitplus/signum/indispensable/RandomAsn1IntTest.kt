package at.asitplus.signum.indispensable

import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.awesn1.nextAsn1Integer
import at.asitplus.awesn1.nextNegativeAsn1Integer
import at.asitplus.awesn1.nextPositiveAsn1Integer
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import org.kotlincrypto.random.CryptoRand

val RandomAsn1IntTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    var twosComplementLimitHit = false
    var positiveLimitHit = false
    var negativeLimitHit = false
    property("nBytes", Arb.int(1, 100), nameFn = { "$it" }) - { nBytes ->
        "Two's complement" {
            val size = CryptoRand.nextAsn1Integer(nBytes).encodeToAsn1ContentBytes().size
            size shouldBeLessThanOrEqual nBytes
            if (size == nBytes) twosComplementLimitHit = true

        }
        "Positive" {
            val size = CryptoRand.nextPositiveAsn1Integer(nBytes).encodeToAsn1ContentBytes().size
            size shouldBeLessThanOrEqual nBytes
            if (size == nBytes) positiveLimitHit = true
        }

        "Negative" {
            val size = CryptoRand.nextNegativeAsn1Integer(nBytes).encodeToAsn1ContentBytes().size
            size shouldBeLessThanOrEqual nBytes
            if(size == nBytes) negativeLimitHit = true
        }
    }

    "limits should be reached" {
        twosComplementLimitHit shouldBe true
        positiveLimitHit shouldBe true
        negativeLimitHit shouldBe true
    }


}