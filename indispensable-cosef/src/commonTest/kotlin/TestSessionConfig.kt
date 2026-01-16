import at.asitplus.testballoon.DataTest
import at.asitplus.testballoon.FreeSpec
import at.asitplus.testballoon.PropertyTest
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testScope
import kotlin.time.Duration.Companion.minutes

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Concurrent)
        .testScope(isEnabled = false, timeout = 20.minutes)
) {
    init {
        DataTest.defaultTestNameMaxLength = -1
        DataTest.defaultDisplayNameMaxLength = -1
        FreeSpec.defaultTestNameMaxLength = -1
        FreeSpec.defaultDisplayNameMaxLength = -1
        PropertyTest.defaultTestNameMaxLength = -1
        PropertyTest.defaultDisplayNameMaxLength = -1
    }
}