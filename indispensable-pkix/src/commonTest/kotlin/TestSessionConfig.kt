import at.asitplus.signum.indispensable.pki.installPkix
import at.asitplus.signum.indispensable.pki.pkixDerTemplate
import at.asitplus.signum.indispensable.pki.RegisteredCertificateExtension
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.Signum
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession() {
    init {
        Signum.setDer(pkixDerTemplate)
        Signum.installPkix()
        Signum.register(RegisteredCertificateExtension)
        Signum.registerAttributeAlias("CUSTOMCN", CommonName.oid)
        Signum.Der
    }
}
