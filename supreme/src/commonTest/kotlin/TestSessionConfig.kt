import de.infix.testBalloon.framework.TestInvocation
import de.infix.testBalloon.framework.TestSession
import de.infix.testBalloon.framework.invocation
import de.infix.testBalloon.framework.testScope
import kotlin.time.Duration.Companion.minutes

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(testConfig = DefaultConfiguration.invocation(TestInvocation.CONCURRENT).testScope(isEnabled = true, timeout = 90.minutes))