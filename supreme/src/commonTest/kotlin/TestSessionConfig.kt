import at.asitplus.signum.Signum
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.apply {
        MatrixTestDefaults { execution = ExecutionMode.Concurrent(64) }
    }
) {
    init { Signum.Der }
    init { Signum.installSupreme() }
}
