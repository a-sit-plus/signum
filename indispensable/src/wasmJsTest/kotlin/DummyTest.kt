package at.asitplus.signum.test
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val WasmJsTest by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 90.minutes)) {
  "This dummy test" {
      "is t jut making sure" shouldNotBe "that WasmJS tests are indeed running"
  }
}