import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val alibi by testSuite {
    test("Tests are working") {
        true shouldBe true
    }
}