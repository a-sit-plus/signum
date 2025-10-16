package at.asitplus.signum
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val Test  by testSuite() {
    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }
}