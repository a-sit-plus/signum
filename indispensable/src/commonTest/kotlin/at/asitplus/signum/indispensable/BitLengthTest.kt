package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.misc.bytes

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.testScope
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.time.Duration.Companion.minutes

val BitLengthTest  by testSuite {
   
    "Small toy values" {
        BitLength(0u).run {
            this shouldBe 0.bit
            this shouldBe 0.bytes
            bits shouldBe 0u
            bytes shouldBe 0u
            bitSpacing shouldBe 0u
        }

        BitLength(1u).run {
            this shouldBe 1.bit
            this shouldNotBe 1.bytes
            bits shouldBe 1u
            bytes shouldBe 1u
            bitSpacing shouldBe 7u
        }

        BitLength(6u).run {
            this shouldBe 6.bit
            this shouldNotBe 1.bytes
            this shouldNotBe 6.bytes
            bits shouldBe 6u
            bytes shouldBe 1u
            bitSpacing shouldBe 2u
        }

        1.bytes shouldBe 8.bit
    }
    "ECDSA values" {
        256.bit.run {
            bits shouldBe 256u
            bytes shouldBe 32u
            bitSpacing shouldBe 0u
        }
        384.bit.run {
            bits shouldBe 384u
            bytes shouldBe 48u
            bitSpacing shouldBe 0u
        }
        521.bit.run {
            bits shouldBe 521u
            bytes shouldBe 66u
            bitSpacing shouldBe 7u
        }
    }
}
