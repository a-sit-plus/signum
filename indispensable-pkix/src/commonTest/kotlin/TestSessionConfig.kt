import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.installPkix
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession() {
    init {
        Signum.installPkix()
    }
}
