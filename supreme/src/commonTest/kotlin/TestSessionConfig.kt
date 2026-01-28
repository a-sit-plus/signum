import at.asitplus.testballoon.DataTest
import at.asitplus.testballoon.FreeSpec
import at.asitplus.testballoon.PropertyTest
import at.asitplus.testballoon.TestBalloonAddons
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
        //Don't make the heap explode
        DataTest.compactByDefault = true
        PropertyTest.compactByDefault = true
        TestBalloonAddons.defaultTestNameMaxLength =-1
    }
}