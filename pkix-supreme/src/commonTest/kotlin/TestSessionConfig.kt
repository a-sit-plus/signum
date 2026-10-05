import at.asitplus.signum.indispensable.pki.signumPkixX509Serializers
import at.asitplus.signum.indispensable.pki.SignumPkix
import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.signum.indispensable.signumAsn1Serializers
import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.apply {
        MatrixTestDefaults { execution = ExecutionMode.Concurrent(8) }
    }
) {
    init {
        DefaultDer.register(signumAsn1Serializers)
        DefaultDer.register(signumPkixX509Serializers)
        SignumPkix.install()
    }
    init { Supreme.init() }
}
