package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.serialization.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.SourceRepresentationStorage
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
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

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

private data class RegisteredSemanticName(val text: String) : OtherName {
    override val oid get() = RegisteredOtherName.oid
    override val sourceRepresentation = SourceRepresentationStorage()
}

private object RegisteredOtherNameProvider : OtherNameAsn1Provider {
    override fun decodeFromAsn1(value: X509GeneralName.Other): OtherName? =
        (value.value as? RegisteredOtherName)?.let { RegisteredSemanticName(it.payload.value.value.trim()) }

    override fun encodeToAsn1(value: OtherName): X509GeneralName.Other? =
        (value as? RegisteredSemanticName)?.let {
            X509GeneralName.Other(RegisteredOtherName(ExplicitlyTagged(Asn1String.UTF8(it.text))))
        }
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
    "Custom OtherNames round-trip through rebuilt SAN, AKI and NameConstraints" {
        isolatedScenario(SignumDerScenarios::class.java, "customOtherName")
    }
    "Selected depth limit reaches embedded constraint bodies" {
        isolatedScenario(SignumDerScenarios::class.java, "depthLimit")
    }
    "PKIX construction leaves DER configurable" {
        isolatedScenario(SignumDerScenarios::class.java, "constructionBeforeDer")
    }
    "JSON attribute and OtherName conversions leave DER configurable" {
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
    fun customOtherName() {
        Signum.setDer(DER {
            serializersModule = SerializersModule {
                polymorphicByOid(X509GeneralName.Other.SemanticValue::class, "RegisteredOtherName") {
                    subtype<RegisteredOtherName>(RegisteredOtherName)
                    catchAll<X509GeneralName.Other.SemanticValue.Generic>()
                }
            }
        })
        Signum.installPkix()
        ServiceLoader.register<OtherNameAsn1Provider>(RegisteredOtherNameProvider)

        val canonical = RegisteredOtherName(ExplicitlyTagged(Asn1String.UTF8("custom")))
        val original = RegisteredOtherName(ExplicitlyTagged(Asn1String.UTF8(" custom ")))
        RegisteredSemanticName("custom").asn1.toRepresentation() shouldBe X509GeneralName.Other(canonical)
        val name = OtherName(X509GeneralName.Other(original)).shouldBeInstanceOf<RegisteredSemanticName>()
        name.text shouldBe "custom"

        val san = SubjectAlternativeName(listOf(name))
        val sanBytes = san.asn1.toDer()
        val decodedSan = CertificateExtension.fromAsn1(sanBytes).shouldBeInstanceOf<SubjectAlternativeName>()
        val decodedSanName = decodedSan.generalNames.single().shouldBeInstanceOf<RegisteredSemanticName>()
        (decodedSanName.asn1.toRepresentation() as X509GeneralName.Other).value
            .shouldBeInstanceOf<RegisteredOtherName>() shouldBe original
        SubjectAlternativeName(decodedSan.generalNames).asn1.toDer() shouldBe sanBytes

        val aki = AuthorityKeyIdentifier(authorityCertIssuer = listOf(name))
        val akiBytes = aki.asn1.toDer()
        val decodedAki = (CertificateExtension.fromAsn1(akiBytes) as AuthorityKeyIdentifier)
        val issuer = decodedAki.authorityCertIssuer.single().shouldBeInstanceOf<RegisteredSemanticName>()
        (issuer.asn1.toRepresentation() as X509GeneralName.Other).value shouldBe original
        AuthorityKeyIdentifier(authorityCertIssuer = decodedAki.authorityCertIssuer).asn1.toDer() shouldBe akiBytes

        val constraints = NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(name))))
        val bytes = constraints.asn1.toDer()
        val decoded = (CertificateExtension.fromAsn1(bytes) as NameConstraints)
        val decodedBase = checkNotNull(decoded.permitted).trees.single().base.shouldBeInstanceOf<RegisteredSemanticName>()
        (decodedBase.asn1.toRepresentation() as X509GeneralName.Other).value shouldBe original
        val rebuilt = NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(decodedBase))))
        rebuilt.asn1.toDer() shouldBe bytes
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
        J509.other(J509.other(mailbox)) shouldBe mailbox
        val original = Json.parseToJsonElement("""{"oid":"1.2.3.999","value":{"native":"opaque"}}""").jsonObject
        val opaque = J509.other(original)
        opaque.oid shouldBe ObjectIdentifier("1.2.3.999")
        J509.other(opaque) shouldBeSameInstanceAs original

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
