import at.asitplus.signum.indispensable.pki.installPkix
import at.asitplus.signum.indispensable.pki.pkixDerTemplate
import at.asitplus.signum.indispensable.pki.RegisteredExtensionProvider
import at.asitplus.signum.indispensable.pki.registeredExtensionSerializers
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.extn.BasicConstraints
import at.asitplus.signum.indispensable.sourceFormat
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession() {
    init {
        // Construction must not initialize DER before applications can configure it.
        check(BasicConstraints(true).sourceFormat == "<no source>")
        Signum.setDer(pkixDerTemplate)
        Signum.installPkix()
        Signum.register(RegisteredExtensionProvider, registeredExtensionSerializers)
        Signum.registerAttributeAlias("CUSTOMCN", CommonName.oid)
        val jsonAttribute = at.asitplus.signum.indispensable.pki.J509.attribute(CommonName("startup"))
        check(at.asitplus.signum.indispensable.pki.J509.attribute(jsonAttribute) is CommonName)
        // This would fail if the JSON path had initialized Signum.Der.
        Signum.registerAsn1Serializers(kotlinx.serialization.modules.SerializersModule {})
        Signum.Der
    }
}
