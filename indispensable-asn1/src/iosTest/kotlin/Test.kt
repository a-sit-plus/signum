package at.asitplus.signum.test
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val Test  by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {

    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }
}