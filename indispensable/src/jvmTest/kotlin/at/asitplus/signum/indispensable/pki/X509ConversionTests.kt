package at.asitplus.signum.indispensable.pki

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)

val X509ConversionTests by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {
    "X509 -> Alg -> X509 is stable" - {
        withData(X509SignatureAlgorithm.entries) {
            it.toX509SignatureAlgorithm() shouldSucceedWith it
            it.algorithm.toX509SignatureAlgorithm() shouldSucceedWith it
        }
    }
}
