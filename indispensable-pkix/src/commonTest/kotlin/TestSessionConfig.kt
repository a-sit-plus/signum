import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.extn.BasicConstraints
import at.asitplus.signum.indispensable.sourceFormat
import de.infix.testBalloon.framework.core.TestSession

class ModuleTestSession : TestSession() {
    init {
        // Construction must not initialize DER before applications can configure it.
        check(BasicConstraints(true).sourceFormat == "<no source>")
        Signum.setDer(pkixDerTemplate)
        ServiceLoader.register<CertificateExtensionProvider>(LenientPkixProvider)
        ServiceLoader.register<GeneralNameFormatProvider>(LenientPkixProvider)
        ServiceLoader.register<OtherNameAsn1Provider>(LenientPkixProvider)
        ServiceLoader.register<PolicyQualifierAsn1Provider>(LenientPkixProvider)
        Signum.installPkix()
        ServiceLoader.register<CertificateExtensionProvider>(RegisteredExtensionProvider)
        ServiceLoader.register<AttributeTypeAndValueProvider>(object : at.asitplus.signum.indispensable.pki.AttributeTypeAndValueProvider {
            override fun oidForName(name: String) = CommonName.oid.takeIf { name == "CUSTOMCN" }
        })
        val jsonAttribute = at.asitplus.signum.indispensable.pki.J509.attribute(CommonName("startup"))
        check(at.asitplus.signum.indispensable.pki.J509.attribute(jsonAttribute) is CommonName)
        // This would fail if the JSON path had initialized Signum.Der.
        Signum.registerAsn1Serializers(kotlinx.serialization.modules.SerializersModule {})
        Signum.Der
    }
}
