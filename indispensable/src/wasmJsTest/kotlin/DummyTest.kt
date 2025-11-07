package at.asitplus.signum.test
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val WasmJsTest by testSuite {
  "This dummy test" {
      "it is just making sure" shouldNotBe "that WasmJS tests are indeed running"
  }
}