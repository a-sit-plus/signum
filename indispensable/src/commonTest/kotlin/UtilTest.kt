package at.asitplus.signum.indispensable

import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.max
import at.asitplus.signum.indispensable.misc.min

import com.ionspin.kotlin.bignum.integer.BigInteger
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val UtilTest by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 90.minutes)) {
   
    "ByteArray.ensureSize" {
        val base = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)

        base.ensureSize(5) shouldBe base
        base.ensureSize(3) shouldBe byteArrayOf(0x03, 0x04, 0x05)
        base.ensureSize(7) shouldBe byteArrayOf(0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05)
    }
    "BitLength" {
        val three = BitLength(3u)
        val four = BitLength(4u)
        val fourAgain = BitLength(4u)

        (four == fourAgain) shouldBe true
        (three < four) shouldBe true
        (four < three) shouldBe false

        BitLength.of(BigInteger.TEN) shouldBe four
        max(three, four) shouldBe fourAgain
        max(four, three) shouldBe fourAgain
        min(three, four) shouldBe three

        three.bytes shouldBe 1u
        four.bytes shouldBe 1u
        BitLength(8u).bytes shouldBe 1u
        BitLength(9u).bytes shouldBe 2u
    }
}
