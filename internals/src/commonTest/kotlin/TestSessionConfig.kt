import de.infix.testBalloon.framework.core.TestInvocation
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testScope
import kotlin.time.Duration.Companion.minutes

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.invocation(TestInvocation.CONCURRENT)
        .testScope(isEnabled = true, timeout = 20.minutes)
)