package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.parse
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe

@OptIn(ExperimentalStdlibApi::class)
class SpecificRegressionTests: FreeSpec({
    "Illegal length encoding leads to inconsistent re-encoding (as featured in: \"this private key sure looks like ASN.1\")" {
        shouldThrow<Asn1Exception> {
            // length < 128 encoded as long form
            Asn1Element.parseFromDerHexString("01811d2b378be969f614283650e8ca3b07eba2289841239513e24fd230e5a538")
        }
        shouldThrow<Asn1Exception> {
            // length > 128 not encoded in the minimum number of bytes
            Asn1Element.parseFromDerHexString("01820080" + "00".repeat(0x80))
        }
    }
})
