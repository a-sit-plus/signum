package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.parse
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

@OptIn(ExperimentalStdlibApi::class)
class SpecificRegressionTests: FreeSpec({
    "Re-encoding inconsistent (as featured in: private key looks like ASN.1)" {
        val data = "01811d2b378be969f614283650e8ca3b07eba2289841239513e24fd230e5a538".hexToByteArray()
        Asn1Element.parse(data).derEncoded shouldBe data
    }
})
