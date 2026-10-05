import at.asitplus.signum.supreme.sign.CursorySignatureSchemeProvider
import at.asitplus.signum.Signum
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.apply {
        MatrixTestDefaults {
            execution = ExecutionMode.Concurrent(64)
        }
    }
) {
    init {
        Signum.setDer(at.asitplus.awesn1.serialization.DER { maxNestingDepth = 80 })
        CursorySignatureSchemeProvider.install()
        Signum.Der
    }
}
