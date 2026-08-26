import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.aroundAll
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.apply {
        MatrixTestDefaults { execution = ExecutionMode.Concurrent(64) }
    }
) {
    init { Supreme.init() }
}
