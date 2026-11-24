package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.serialization.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.extn.AuthorityKeyIdentifier
import at.asitplus.signum.indispensable.pki.extn.BasicConstraints
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtree
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtrees
import at.asitplus.signum.indispensable.pki.extn.NameConstraints
import at.asitplus.signum.indispensable.pki.x500.OtherName
import at.asitplus.signum.indispensable.pki.x500.SmtpUtf8Mailbox
import at.asitplus.signum.indispensable.sourceFormat
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.modules.SerializersModule

@Serializable
internal data class RegisteredOtherName(
    @Asn1Tag(0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    val payload: ExplicitlyTagged<Asn1String.UTF8>,
) : X509GeneralName.Other.SemanticValue {
    override val oid: ObjectIdentifier get() = Companion.oid
    companion object : OidProvider<RegisteredOtherName> {
        override val oid = ObjectIdentifier("1.2.3.123456789")
    }
}

private data class CustomOtherName(val text: String) : OtherName() {
    override val oid get() = RegisteredOtherName.oid
}

private object CustomOtherNameProvider : OtherNameAsn1Provider, GeneralNameFormatProvider {
    override fun decodeFromAsn1(value: X509GeneralName.Other): OtherName? =
        (value.value as? RegisteredOtherName)?.let { CustomOtherName(it.payload.value.value) }

    override fun encodeToAsn1(value: OtherName): X509GeneralName.Other? =
        (value as? CustomOtherName)?.let {
            X509GeneralName.Other(RegisteredOtherName(ExplicitlyTagged(Asn1String.UTF8(it.text))))
        }

    override fun decodeFromAsn1(generalName: X509GeneralName): GeneralName? =
        (generalName as? X509GeneralName.Other)?.let { decodeFromAsn1(it) }

    override fun encodeToAsn1(generalName: GeneralName): X509GeneralName? = null
}

internal data class RegisteredCertificateExtension(val text: String) : CertificateExtension {
    override val oid get() = Companion.oid
    override val critical = false
    override val sourceRepresentation = at.asitplus.signum.indispensable.SourceRepresentationStorage()
    companion object { val oid = ObjectIdentifier("1.2.3.123456790") }
}

internal object RegisteredExtensionProvider : CertificateExtensionProvider {
    override fun decodeFromAsn1(asn1: at.asitplus.awesn1.crypto.pki.X509CertificateExtension): CertificateExtension? =
        if (asn1.oid == RegisteredCertificateExtension.oid)
            RegisteredCertificateExtension(Signum.Der.decodeFromByteArray<Asn1String.UTF8>(asn1.value).value)
        else null
    override fun encodeToAsn1(value: CertificateExtension): at.asitplus.awesn1.crypto.pki.X509CertificateExtension? =
        (value as? RegisteredCertificateExtension)?.let {
            at.asitplus.awesn1.crypto.pki.X509CertificateExtension(it.oid, it.critical, Signum.Der.encodeToByteArray(Asn1String.UTF8(it.text)))
        }
}

val SignumDerIsolationTest by matrixSuite {
    "Bootstrap preserves custom configuration and seals registration" {
        isolatedScenario(SignumDerScenarios::class.java, "bootstrap")
    }
    "Provider decoding needs no contextual semantic serializers" {
        isolatedScenario(SignumDerScenarios::class.java, "providerDecoding")
    }
    "Rejected serializer registration leaves the active provider usable" {
        isolatedScenario(SignumDerScenarios::class.java, "rejectedRegistration")
    }
    "Custom OtherName providers reach nested AKI and NameConstraints codecs" {
        isolatedScenario(SignumDerScenarios::class.java, "customOtherName")
    }
    "Selected depth limit reaches embedded constraint bodies" {
        isolatedScenario(SignumDerScenarios::class.java, "depthLimit")
    }
    "PKIX construction leaves DER configurable" {
        isolatedScenario(SignumDerScenarios::class.java, "constructionBeforeDer")
    }
    "JSON attribute and OtherName codecs leave DER configurable" {
        isolatedScenario(SignumDerScenarios::class.java, "jsonBeforeDer")
    }
    "Attribute providers resolve custom aliases" {
        isolatedScenario(SignumDerScenarios::class.java, "customAlias")
    }
}

internal object SignumDerScenarios {
    @JvmStatic
    fun bootstrap() {
        // Neither core nor PKIX serializers are pre-included.
        val template = DER {
            maxNestingDepth = 80
            maxInputLength = 1_000_000
        }
        Signum.setDer(template)
        Signum.installPkix()
        Signum.Der.configuration.maxNestingDepth shouldBe 80
        Signum.Der.configuration.maxInputLength shouldBe 1_000_000L
        (Signum.Der === template) shouldBe false
        Signum.Der shouldBeSameInstanceAs Signum.Der
        shouldThrowAny { Signum.setDer(template) }
        shouldThrowAny { Signum.registerAsn1Serializers(SerializersModule {}) }
    }

    @JvmStatic
    fun providerDecoding() {
        Signum.installPkix()
        ServiceLoader.register<CertificateExtensionProvider>(RegisteredExtensionProvider)
        Signum.Der.serializersModule.getContextual(CertificateExtension::class) shouldBe null
        Signum.Der.serializersModule.getContextual(GeneralName::class) shouldBe null
        Signum.Der.serializersModule.getContextual(at.asitplus.signum.indispensable.pki.attributes.CommonName::class) shouldBe null
        val source = RegisteredCertificateExtension("custom")
        val bytes = source.asn1.toDer()
        val concrete = CertificateExtension.fromAsn1(bytes).shouldBeInstanceOf<RegisteredCertificateExtension>()
        val generic = CertificateExtension.fromAsn1(bytes)
        generic.shouldBeInstanceOf<RegisteredCertificateExtension>()
        concrete shouldBe source
        concrete.asn1.toDer() shouldBe bytes
        requireNotNull(concrete.asn1.toRepresentation())
    }

    @JvmStatic
    fun rejectedRegistration() {
        Signum.installPkix()
        val der = Signum.Der
        ServiceLoader.register<CertificateExtensionProvider>(RegisteredExtensionProvider)
        shouldThrowAny { Signum.registerAsn1Serializers(SerializersModule {}) }
        Signum.Der shouldBeSameInstanceAs der
        val source = RegisteredCertificateExtension("still registered")
        CertificateExtension.fromAsn1(source.asn1.toRepresentation()) shouldBe source
    }

    @JvmStatic
    @OptIn(SignumInternals::class)
    fun customOtherName() {
        Signum.setDer(DER {
            serializersModule = SerializersModule {
                polymorphicByOid(X509GeneralName.Other.SemanticValue::class, "RegisteredOtherName") {
                    subtype<RegisteredOtherName>(RegisteredOtherName)
                    catchAll<X509GeneralName.Other.SemanticValue.Generic>()
                }
            }
        })
        val source = X509GeneralName.Other(RegisteredOtherName(ExplicitlyTagged(Asn1String.UTF8("custom"))))
        val fallback = GeneralName.fromAsn1(source).shouldBeInstanceOf<GeneralName.Unknown>()
        fallback.asn1.toRepresentation() shouldBe source

        ServiceLoader.register<GeneralNameFormatProvider>(CustomOtherNameProvider)
        Signum.installPkix()
        // PKIX's OtherName lookup declines first, leaving the lower-priority GeneralName provider a chance.
        GeneralName.fromAsn1(source) shouldBe CustomOtherName("custom")

        ServiceLoader.register<OtherNameAsn1Provider>(CustomOtherNameProvider)
        val name = OtherName(source).shouldBeInstanceOf<CustomOtherName>()
        name.text shouldBe "custom"
        CustomOtherName("custom").asn1.toRepresentation() shouldBe source
        val aki = AuthorityKeyIdentifier(authorityCertIssuer = listOf(name))
        val akiBytes = aki.asn1.toDer()
        val decodedAki = (CertificateExtension.fromAsn1(akiBytes) as AuthorityKeyIdentifier)
        decodedAki.authorityCertIssuer.single().shouldBeInstanceOf<CustomOtherName>().text shouldBe name.text
        (decodedAki.authorityCertIssuer.single().asn1.toRepresentation() as X509GeneralName.Other).value
            .shouldBeInstanceOf<RegisteredOtherName>()
        decodedAki.asn1.toDer() shouldBe akiBytes

        val constraints = NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(name))))
        val bytes = constraints.asn1.toDer()
        val decoded = (CertificateExtension.fromAsn1(bytes) as NameConstraints)
        val base = checkNotNull(decoded.permitted).trees.single().base
        base.shouldBeInstanceOf<CustomOtherName>().text shouldBe name.text
        (base.asn1.toRepresentation() as X509GeneralName.Other).value
            .shouldBeInstanceOf<RegisteredOtherName>()
        decoded.asn1.toDer() shouldBe bytes
    }

    @JvmStatic
    fun depthLimit() {
        Signum.setDer(DER { maxNestingDepth = 80 })
        Signum.installPkix()
        var payload: Asn1Element = at.asitplus.awesn1.encoding.Asn1.Null()
        repeat(40) { payload = Asn1Sequence(listOf(payload)) }
        val name = OtherName(X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(ObjectIdentifier("1.2.3.4.99"), payload)))
        val source = NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(name))))
        val decoded = (CertificateExtension.fromAsn1(source.asn1.toDer()) as NameConstraints)
        decoded.permitted!!.trees.size shouldBe 1
    }

    @JvmStatic
    fun constructionBeforeDer() {
        // Construction must not initialize DER before applications can configure it.
        BasicConstraints(true).sourceFormat shouldBe "<no source>"
        shouldNotThrowAny { Signum.setDer(DER {}) }
    }

    @JvmStatic
    fun jsonBeforeDer() {
        Signum.installPkix()
        val jsonAttribute = J509.attribute(CommonName("startup"))
        J509.attribute(jsonAttribute).shouldBeInstanceOf<CommonName>().text shouldBe "startup"

        val mailbox = SmtpUtf8Mailbox("mé@example.test")
        val known = J509.other(J509.other(mailbox)).shouldBeInstanceOf<SmtpUtf8Mailbox>()
        known shouldBe mailbox
        val jsonOtherName = Json.parseToJsonElement("""{"oid":"1.2.3.999","value":{"native":"opaque"}}""").jsonObject
        val unknown = J509.other(jsonOtherName).shouldBeInstanceOf<OtherName.Unknown>()
        unknown.oid shouldBe ObjectIdentifier("1.2.3.999")
        J509.other(unknown) shouldBeSameInstanceAs jsonOtherName

        // This would fail if the JSON path had initialized Signum.Der.
        shouldNotThrowAny { Signum.registerAsn1Serializers(SerializersModule {}) }
    }

    @JvmStatic
    fun customAlias() {
        Signum.installPkix()
        ServiceLoader.register<AttributeTypeAndValueProvider>(object : AttributeTypeAndValueProvider {
            override fun decodeATV(
                key: AttributeTypeAndValueProvider.Key,
                value: AttributeTypeAndValueProvider.Value,
            ): AttributeTypeAndValue? =
                if (key == AttributeTypeAndValueProvider.Key("CUSTOMCN") && value is AttributeTypeAndValueProvider.StringValue)
                    CommonName(value.str)
                else null

            override fun encodeATV(
                atv: AttributeTypeAndValue,
            ): Pair<AttributeTypeAndValueProvider.Key, AttributeTypeAndValueProvider.Value>? = null
        })
        AttributeTypeAndValue.fromString("customcn", "Alice").shouldBeInstanceOf<CommonName>().text shouldBe "Alice"
    }
}
