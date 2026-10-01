import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.signum.indispensable.signumX509Serializers
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession() {
    init { DefaultDer.register(signumX509Serializers) }
}
