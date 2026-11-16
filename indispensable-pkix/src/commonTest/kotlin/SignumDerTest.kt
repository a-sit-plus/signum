@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtree
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule

val SignumDerTest by matrixSuite {
    "Malformed recognized extension bodies are unknown and round-trip" {
        for (oid in listOf(KnownOIDs.nameConstraints_2_5_29_30, KnownOIDs.certificatePolicies_2_5_29_32, KnownOIDs.policyMappings)) {
            val model = at.asitplus.awesn1.crypto.pki.X509CertificateExtension(oid, true, byteArrayOf(0x30, 0x01))
            val direct = CertificateExtension.fromAsn1(model).shouldBeInstanceOf<CertificateExtension.Unknown>()
            direct.oid shouldBe oid
            direct.critical shouldBe true
            direct.asn1.toRepresentation() shouldBeSameInstanceAs model
            direct.lookupResult.message.isNullOrEmpty() shouldBe false

            val bytes = Signum.Der.encodeToByteArray(model)
            val decoded = CertificateExtension.fromAsn1(bytes)
                .shouldBeInstanceOf<CertificateExtension.Unknown>()
            decoded.oid shouldBe oid
            decoded.critical shouldBe true
            decoded.lookupResult.message.isNullOrEmpty() shouldBe false
            (decoded).asn1.toDer() shouldBe bytes
        }
        val opaque = CertificateExtension(ObjectIdentifier("1.2.3.4.99"), true, byteArrayOf(0x30, 0x01))
        val bytes = (opaque).asn1.toDer()
        CertificateExtension.fromAsn1(bytes).asn1.toDer() shouldBe bytes
    }

    "GeneralSubtree preserves original wire form with semantic equality" {
        val name = DNSName(Asn1String.IA5("example.com"))
        val omitted = GeneralSubtree(name)
        val explicit = GeneralSubtree.fromAsn1(GeneralSubtree.Asn1Representation(name.asn1.toRepresentation(), Asn1Integer(0)))
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
