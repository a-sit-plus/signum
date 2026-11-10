@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.asn1

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.serialization.*
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.signum.indispensable.pki.x500.OtherName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.*

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

internal data class RegisteredCertificateExtension(val text: String) : CertificateExtension {
    override val oid get() = Companion.oid
    override val critical = false
    @at.asitplus.signum.SignumInternals
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

// Selected once by the test-session constructor; neither core nor PKIX serializers are pre-included.
internal val pkixDerTemplate = DER {
    maxNestingDepth = 80
    maxInputLength = 1_000_000
    serializersModule = SerializersModule {
        polymorphicByOid(X509GeneralName.Other.SemanticValue::class, "RegisteredOtherName") {
            subtype<RegisteredOtherName>(RegisteredOtherName)
            catchAll<X509GeneralName.Other.SemanticValue.Generic>()
        }
    }
}

val SignumDerTest by matrixSuite {
    "Bootstrap preserves custom configuration and seals registration" {
        Signum.Der.configuration.maxNestingDepth shouldBe 80
        Signum.Der.configuration.maxInputLength shouldBe 1_000_000L
        (Signum.Der === pkixDerTemplate) shouldBe false
        Signum.Der shouldBeSameInstanceAs Signum.Der
        shouldThrowAny { Signum.setDer(pkixDerTemplate) }
        shouldThrowAny { Signum.registerAsn1Serializers(SerializersModule {}) }
    }

    "Provider decoding needs no contextual semantic serializers" {
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
        Signum.attributeOidFor("customcn") shouldBe at.asitplus.signum.indispensable.pki.attributes.CommonName.oid
    }

    "Rejected serializer registration leaves the active provider usable" {
        shouldThrowAny { Signum.register(RegisteredExtensionProvider, SerializersModule {}) }
        val source = RegisteredCertificateExtension("still registered")
        CertificateExtension.fromAsn1(source.asn1.toRepresentation()) shouldBe source
    }

    "Custom otherName registration reaches nested AKI and NameConstraints codecs" {
        val name = OtherName(X509GeneralName.Other(RegisteredOtherName(ExplicitlyTagged(Asn1String.UTF8("custom")))))
        val aki = AuthorityKeyIdentifier(authorityCertIssuer = listOf(name))
        val akiBytes = aki.asn1.toDer()
        val decodedAki = (CertificateExtension.fromAsn1(akiBytes) as AuthorityKeyIdentifier)
        (decodedAki.authorityCertIssuer.single().asn1.toRepresentation() as X509GeneralName.Other).value
            .shouldBeInstanceOf<RegisteredOtherName>()
        decodedAki.asn1.toDer() shouldBe akiBytes

        val constraints = NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(name))))
        val bytes = constraints.asn1.toDer()
        val decoded = (CertificateExtension.fromAsn1(bytes) as NameConstraints)
        (decoded.permitted!!.trees.single().base.asn1.toRepresentation() as X509GeneralName.Other).value
            .shouldBeInstanceOf<RegisteredOtherName>()
        decoded.asn1.toDer() shouldBe bytes
    }

    "Selected depth limit reaches embedded constraint bodies" {
        var payload: Asn1Element = at.asitplus.awesn1.encoding.Asn1.Null()
        repeat(40) { payload = Asn1Sequence(listOf(payload)) }
        val name = OtherName(X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(ObjectIdentifier("1.2.3.4.99"), payload)))
        val source = NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(name))))
        val decoded = (CertificateExtension.fromAsn1(source.asn1.toDer()) as NameConstraints)
        decoded.permitted!!.trees.size shouldBe 1
    }

    "Malformed recognized extension bodies are invalid and round-trip" {
        for (oid in listOf(KnownOIDs.nameConstraints_2_5_29_30, KnownOIDs.certificatePolicies_2_5_29_32, KnownOIDs.policyMappings)) {
            val model = at.asitplus.awesn1.crypto.pki.X509CertificateExtension(oid, true, byteArrayOf(0x30, 0x01))
            val direct = CertificateExtension.fromAsn1(model).shouldBeInstanceOf<InvalidCertificateExtension>()
            direct.oid shouldBe oid
            direct.critical shouldBe true
            direct.asn1.toRepresentation() shouldBeSameInstanceAs model
            direct.failure.message.isNullOrEmpty() shouldBe false

            val bytes = Signum.Der.encodeToByteArray(model)
            val decoded = CertificateExtension.fromAsn1(bytes)
                .shouldBeInstanceOf<InvalidCertificateExtension>()
            decoded.oid shouldBe oid
            decoded.critical shouldBe true
            decoded.failure.message.isNullOrEmpty() shouldBe false
            (decoded).asn1.toDer() shouldBe bytes
        }
        val opaque = CertificateExtension(ObjectIdentifier("1.2.3.4.99"), true, byteArrayOf(0x30, 0x01))
        val bytes = (opaque).asn1.toDer()
        CertificateExtension.fromAsn1(bytes).asn1.toDer() shouldBe bytes
    }

    "GeneralSubtree preserves original wire form with semantic equality" {
        val name = DNSName(Asn1String.IA5("example.com"))
        val omitted = GeneralSubtree(name)
        val explicit = GeneralSubtree.fromAsn1(X509GeneralSubtree(name.asn1.toRepresentation(), Asn1Integer(0)))
        explicit shouldBe omitted
        explicit.hashCode() shouldBe omitted.hashCode()
        explicit.asn1.toRepresentation() shouldBeSameInstanceAs explicit.asn1.toRepresentation()
        val bytes = explicit.asn1.toDer()
        GeneralSubtree.fromAsn1(bytes).asn1.toDer() shouldBe bytes
    }

    "GeneralSubtree permits an independent serializer without selecting the X509 shape" {
        val subtree = GeneralSubtree(DNSName(Asn1String.IA5("example.com")))
        val json = Json {
            serializersModule = SerializersModule {
                contextual(GeneralSubtree::class, object : KSerializer<GeneralSubtree> {
                    override val descriptor = PrimitiveSerialDescriptor("SemanticSubtree", PrimitiveKind.STRING)
                    override fun serialize(encoder: Encoder, value: GeneralSubtree) = encoder.encodeString(value.base.toString())
                    override fun deserialize(decoder: Decoder) = GeneralSubtree(DNSName(Asn1String.IA5(decoder.decodeString())))
                })
            }
        }
        val encoded = json.encodeToString(subtree)
        encoded shouldBe "\"example.com\""
        json.decodeFromString<GeneralSubtree>(encoded) shouldBe subtree
    }
}
