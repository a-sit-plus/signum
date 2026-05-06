package at.asitplus.signum.indispensable

import at.asitplus.awesn1.BitSet

import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.testScope
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.minutes

val BitSetIteratorTest  by matrixSuite {
   
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