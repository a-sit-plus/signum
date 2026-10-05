package at.asitplus.signum.indispensable.pki

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

internal class RegisteredCertificateExtension private constructor(
    src: at.asitplus.awesn1.crypto.pki.X509CertificateExtension,
) : X509CertificateExtension(src) {
    constructor(value: String) : this(at.asitplus.awesn1.crypto.pki.X509CertificateExtension(
        Companion.oid, false, Signum.Der.encodeToByteArray(Asn1String.UTF8(value))))

    companion object : CertificateExtension.Descriptor<RegisteredCertificateExtension> {
        override val oid = ObjectIdentifier("1.2.3.123456790")
        override fun fromAsn1Representation(src: at.asitplus.awesn1.crypto.pki.X509CertificateExtension) =
            RegisteredCertificateExtension(src)
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

    "One descriptor registration installs concrete and generic extension decoding" {
        val source = RegisteredCertificateExtension("custom")
        val bytes = Signum.Der.encodeToByteArray(source)
        val concrete = Signum.Der.decodeFromByteArray<RegisteredCertificateExtension>(bytes)
        val generic = Signum.Der.decodeFromByteArray<CertificateExtension>(bytes)
        generic.shouldBeInstanceOf<RegisteredCertificateExtension>()
        concrete shouldBe source
        Signum.Der.encodeToByteArray(concrete) shouldBe bytes
        requireNotNull(concrete.representations[X509])
        Signum.attributeOidFor("customcn") shouldBe at.asitplus.signum.indispensable.pki.attributes.CommonName.oid
    }

    "Rejected descriptor registration does not replace a registered descriptor" {
        shouldThrowAny { Signum.register(RegisteredCertificateExtension) }
        Signum.certificateExtensionDescriptorFor(RegisteredCertificateExtension.oid)
            .shouldBeSameInstanceAs(RegisteredCertificateExtension)
    }

    "Custom otherName registration reaches nested AKI and NameConstraints codecs" {
        val name = OtherName(X509GeneralName.Other(RegisteredOtherName(ExplicitlyTagged(Asn1String.UTF8("custom")))))
        val aki = AuthorityKeyIdentifier(authorityCertIssuer = listOf(name))
        val akiBytes = Signum.Der.encodeToByteArray(aki)
        val decodedAki = Signum.Der.decodeFromByteArray<AuthorityKeyIdentifier>(akiBytes)
        (decodedAki.authorityCertIssuer.single().asn1Representation as X509GeneralName.Other).value
            .shouldBeInstanceOf<RegisteredOtherName>()
        Signum.Der.encodeToByteArray(decodedAki) shouldBe akiBytes

        val constraints = NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(name))))
        val bytes = Signum.Der.encodeToByteArray(constraints)
        val decoded = Signum.Der.decodeFromByteArray<NameConstraints>(bytes)
        (decoded.permitted!!.trees.single().base.asn1Representation as X509GeneralName.Other).value
            .shouldBeInstanceOf<RegisteredOtherName>()
        Signum.Der.encodeToByteArray(decoded) shouldBe bytes
    }

    "Selected depth limit reaches embedded constraint bodies" {
        var payload: Asn1Element = at.asitplus.awesn1.encoding.Asn1.Null()
        repeat(40) { payload = Asn1Sequence(listOf(payload)) }
        val name = OtherName(X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(ObjectIdentifier("1.2.3.4.99"), payload)))
        val source = NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(name))))
        val decoded = Signum.Der.decodeFromByteArray<NameConstraints>(Signum.Der.encodeToByteArray(source))
        decoded.permitted!!.trees.size shouldBe 1
    }

    "Known malformed extension bodies throw; unknown bodies remain opaque" {
        for (oid in listOf(KnownOIDs.nameConstraints_2_5_29_30, KnownOIDs.certificatePolicies_2_5_29_32, KnownOIDs.policyMappings)) {
            val model = at.asitplus.awesn1.crypto.pki.X509CertificateExtension(oid, true, byteArrayOf(0x30, 0x01))
            shouldThrowAny { CertificateExtension.fromAsn1Representation(model) }
            shouldThrowAny { Signum.Der.decodeFromByteArray<CertificateExtension>(Signum.Der.encodeToByteArray(model)) }
        }
        val opaque = CertificateExtension(ObjectIdentifier("1.2.3.4.99"), true, byteArrayOf(0x30, 0x01))
        val bytes = Signum.Der.encodeToByteArray<CertificateExtension>(opaque)
        Signum.Der.encodeToByteArray(Signum.Der.decodeFromByteArray<CertificateExtension>(bytes)) shouldBe bytes
    }

    "GeneralSubtree preserves original wire form with semantic equality" {
        val name = DNSName(Asn1String.IA5("example.com"))
        val omitted = GeneralSubtree(name)
        val explicit = GeneralSubtree.fromAsn1Representation(X509GeneralSubtree(name, Asn1Integer(0)))
        explicit shouldBe omitted
        explicit.hashCode() shouldBe omitted.hashCode()
        explicit.asn1Representation shouldBeSameInstanceAs explicit.representations[X509]
        val bytes = Signum.Der.encodeToByteArray(explicit)
        Signum.Der.encodeToByteArray(Signum.Der.decodeFromByteArray<GeneralSubtree>(bytes)) shouldBe bytes
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
