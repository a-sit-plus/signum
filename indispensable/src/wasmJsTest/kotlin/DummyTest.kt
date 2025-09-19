package at.asitplus.signum.test
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldNotBe

val WasmJsTest by testSuite {
  "This dummy test" {
      "is t jut making sure" shouldNotBe "that WasmJS tests are indeed running"
  }
}