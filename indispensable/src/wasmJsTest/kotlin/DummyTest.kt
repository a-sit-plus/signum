package at.asitplus.signum.test
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val WasmJsTest by testSuite {
  "This dummy test" {
      "it is just making sure" shouldNotBe "that WasmJS tests are indeed running"
  }
}