import at.asitplus.signum.SecureRandom
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.shouldBe

val SecureRandomTest by testSuite {
    withData(List(33) { it }) { bitCount ->
        // 0 bits: always zero; nothing to loop for
        if (bitCount == 0) {
            val rnd = SecureRandom.nextBits(0)
            rnd shouldBe 0
            return@withData
        }

        // Always: upper bits must be zero
        val rnd1 = SecureRandom.nextBits(bitCount)
        rnd1.countLeadingZeroBits() shouldBeGreaterThanOrEqual (32 - bitCount)


        // Loop until the highest of the produced bits is set (bitCount-1)
        val targetMask = 1 shl (bitCount - 1)
        var rnd = rnd1
        println("First Try: $rnd")
        var trials =1uL
        while ((rnd and targetMask) == 0) {
            rnd = SecureRandom.nextBits(bitCount)
            println("Trial ${trials++}: $rnd")
            rnd.countLeadingZeroBits() shouldBeGreaterThanOrEqual (32 - bitCount)
        }
    }
}