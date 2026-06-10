package at.asitplus.signum.test
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val Test  by matrixSuite {

    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }
}