package at.asitplus.signum.indispensable.asn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.throwables.shouldThrow

@OptIn(ExperimentalStdlibApi::class)
val SpecificRegressionTests by testSuite {
    "Illegal length encoding" {
        shouldThrow<Asn1Exception> {
            // length < 128 encoded as long form
            Asn1Element.parseFromDerHexString("01811d2b378be969f614283650e8ca3b07eba2289841239513e24fd230e5a538")
        }
        shouldThrow<Asn1Exception> {
            // length > 128 not encoded in the minimum number of bytes
            Asn1Element.parseFromDerHexString("01820080" + "00".repeat(0x80))
        }
    }
}
