import at.asitplus.signum.indispensable.pki.signumPkixX509Serializers
import at.asitplus.signum.indispensable.pki.SignumPkix
import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.signum.indispensable.signumAsn1Serializers
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession() {
    init {
        DefaultDer.register(signumAsn1Serializers)
        DefaultDer.register(signumPkixX509Serializers)
        SignumPkix.install()
    }
}
