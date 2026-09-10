import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.apply {
        MatrixTestDefaults {
            execution = ExecutionMode.Concurrent(64)
        }
    }
)
