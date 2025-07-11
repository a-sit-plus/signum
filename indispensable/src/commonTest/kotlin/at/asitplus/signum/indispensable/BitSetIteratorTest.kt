package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.BitSet
import at.asitplus.signum.test.JUnitXmlReporter
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

class BitSetIteratorTest : FreeSpec({
    extensions(JUnitXmlReporter())
    "simple test" {
        var remaining = 1
        BitSet(1).apply {
            set(0)
        }.forEach { _ ->
            remaining -= 1
        }
        remaining shouldBe 0
    }
})