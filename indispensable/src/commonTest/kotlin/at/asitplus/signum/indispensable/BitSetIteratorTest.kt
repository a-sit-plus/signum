package at.asitplus.signum.indispensable

import at.asitplus.awesn1.BitSet
import at.asitplus.awesn1.set
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val BitSetIteratorTest by testSuite {

    "simple test" {
        var remaining = 1
        BitSet(1).apply {
            set(0)
        }.forEach { _ ->
            remaining -= 1
        }
        remaining shouldBe 0
    }
}