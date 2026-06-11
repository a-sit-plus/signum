package at.asitplus.signum.test
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val WasmJsTest by matrixSuite {
  "This dummy test" {
      "it is just making sure" shouldNotBe "that WasmJS tests are indeed running"
  }
}