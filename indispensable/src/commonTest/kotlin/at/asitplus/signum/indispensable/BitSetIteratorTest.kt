package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.BitSet

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.testScope
import de.infix.testBalloon.framework.testSuite
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.minutes

val BitSetIteratorTest  by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {
   
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