import at.asitplus.signum.SecureRandom
import at.asitplus.test.Target
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.shouldBe
import kotlin.random.Random


val SecureRandomTest by testSuite {

    //This is precisely why we need a Random-compatible SecureRandom
    var random: Random = when (Target.current) {
        Target.JS_BROWSER, Target.JS_NODE, Target.JS_WEBWORKER, Target.JS_GENERIC, Target.WASMJS -> Random.Default
        else -> SecureRandom
    }

    withData(List(33) { it }) { bitCount ->
        // 0 bits: always zero; nothing to loop for
        if (bitCount == 0) {
            val rnd = random.nextBits(0)
            rnd shouldBe 0
            return@withData
        }

        // Always: upper bits must be zero
        val rnd1 = random.nextBits(bitCount)
        rnd1.countLeadingZeroBits() shouldBeGreaterThanOrEqual (32 - bitCount)

        // Loop until the highest of the produced bits is set (bitCount-1)
        val targetMask = 1 shl (bitCount - 1)
        var rnd = rnd1
        var trials = 1uL
        while ((rnd and targetMask) == 0) {
            rnd = random.nextBits(bitCount)
            rnd.countLeadingZeroBits() shouldBeGreaterThanOrEqual (32 - bitCount)
        }
    }
}