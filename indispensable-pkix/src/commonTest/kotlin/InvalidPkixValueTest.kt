@file:OptIn(at.asitplus.signum.SignumInternals::class, at.asitplus.signum.indispensable.pki.ExperimentalPkiApi::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.pki.attributes.*
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

val InvalidPkixValueTest by matrixSuite {
    "Recognized invalid name payloads retain their original source" {
        val sources = listOf<X509GeneralName>(
            X509GeneralName.Dns("bad name"), X509GeneralName.Rfc822("two@@example.com"),
            X509GeneralName.UniformResourceIdentifier(""),
            Signum.Der.decodeFromByteArray(X509GeneralName.serializer(), "870101".hexToByteArray()),
            X509GeneralName.EdiParty(emptyList()),
        )
        sources.forEach { source ->
            val name = GeneralName.fromAsn1(source).shouldBeInstanceOf<InvalidGeneralName>()
            name.isInvalid shouldBe true
            name.isValid shouldBe false
            ((name as GeneralName) is ServiceLoader.UnknownShim) shouldBe false
            name.asn1.toRepresentation() shouldBeSameInstanceAs source
            GeneralName.fromAsn1(name.asn1.toDer()).shouldBeInstanceOf<InvalidGeneralName>()
            shouldThrowAny { name.constrains(DNSName("example.com")) }
        }
    }

    "Invalid ATVs survive name and certificate construction and parsing" {
        val sources = listOf(
            X500AttributeTypeAndValue(CommonName.oid, Asn1Integer(1).encodeToTlv()),
            X500AttributeTypeAndValue(CommonName.oid, Asn1Element.parse("160180".hexToByteArray())),
            X500AttributeTypeAndValue(Country.oid, Asn1String.UTF8("Ä").encodeToTlv()),
        )
        sources.forEach { source ->
            val atv = AttributeTypeAndValue.fromAsn1(source).shouldBeInstanceOf<InvalidAttributeTypeAndValue>()
            atv.oid shouldBe source.oid
            atv.asn1.toRepresentation() shouldBeSameInstanceAs source
            val name = Name(listOf(RelativeDistinguishedName(atv)))
            name.isValid shouldBe false
            Name.fromAsn1(name.asn1.toDer()).relativeDistinguishedNames.single().attrsAndValues.single()
                .shouldBeInstanceOf<InvalidAttributeTypeAndValue>()
            val contents = TbsCertificate(
                com.ionspin.kotlin.bignum.integer.BigInteger.ONE,
                at.asitplus.signum.indispensable.sign.EcdsaAlgorithm.withSHA256,
                name, kotlin.time.Instant.fromEpochSeconds(1), kotlin.time.Instant.fromEpochSeconds(2), name,
                ECCurve.SECP_256_R_1.generator.asPublicKey(),
            )
            TbsCertificate.fromAsn1(contents.asn1.toDer()).subjectName.relativeDistinguishedNames.single()
                .attrsAndValues.single().shouldBeInstanceOf<InvalidAttributeTypeAndValue>()
        }
        val unknown = AttributeTypeAndValue(ObjectIdentifier("1.2.3.999"), Asn1Integer(1).encodeToTlv())
        unknown.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
        unknown.isValid shouldBe null
        RelativeDistinguishedName(TextAttributeTypeAndValue(Country.oid, "Ä")).isValid shouldBe false
        shouldThrowAny { RelativeDistinguishedName(emptySet()) }
    }

    "Malformed known CSR attributes and OtherNames differ from unknown OIDs" {
        val csrSource = Pkcs10CsrAttribute(CsrAttribute.EXTENSION_REQUEST_OID, setOf(Asn1Integer(1).encodeToTlv()))
        val csr = CsrAttribute.fromAsn1(csrSource).shouldBeInstanceOf<InvalidCsrAttribute>()
        csr.asn1.toRepresentation() shouldBeSameInstanceAs csrSource
        CsrAttribute.fromAsn1(csr.asn1.toDer()).shouldBeInstanceOf<InvalidCsrAttribute>()
        CsrAttribute(ObjectIdentifier("1.2.3.999"), Asn1Integer(1).encodeToTlv())
            .shouldBeInstanceOf<ServiceLoader.UnknownShim>()

        val otherSource = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            MacAddressName.OID, Asn1String.UTF8("wrong type").encodeToTlv(),
        ))
        val other = OtherName(otherSource).shouldBeInstanceOf<InvalidOtherName>()
        other.oid shouldBe MacAddressName.OID
        other.isValid shouldBe false
        (other.asn1.toRepresentation() as X509GeneralName.Other).value shouldBeSameInstanceAs otherSource.value
        OtherName(X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            ObjectIdentifier("1.2.3.999"), Asn1Integer(1).encodeToTlv(),
        ))).shouldBeInstanceOf<ServiceLoader.UnknownShim>()
    }

    "Invalid qualifiers stay inside interpreted certificate policies" {
        val oid = ObjectIdentifier("1.2.3.4")
        val body = Signum.Der.encodeToByteArray(ListSerializer(InvalidPolicyWire.serializer()), listOf(
            InvalidPolicyWire(oid, listOf(InvalidQualifierWire(CpsUri("").oid, Asn1Integer(1).encodeToTlv()))),
        ))
        val policies = CertificateExtension.fromAsn1(X509CertificateExtension(CertificatePolicies.oid, false, body))
            .shouldBeInstanceOf<CertificatePolicies>()
        val qualifier = policies.certificatePolicies.single().policyQualifiers.single()
        qualifier.shouldBeInstanceOf<InvalidPolicyQualifierInfo>()
        qualifier.isInvalid shouldBe true
        CertificatePolicies(policies.certificatePolicies).asn1.toRepresentation().value shouldBe body
    }

    "Invalid values can retain a non-ASN.1 source for independent recovery" {
        val raw = Json.parseToJsonElement("""{"oid":"2.5.4.6","text":"Ä","extra":42}""").jsonObject
        val invalid = J509.attribute(raw).shouldBeInstanceOf<InvalidAttributeTypeAndValue>()
        J509.attribute(invalid) shouldBeSameInstanceAs raw
        shouldThrowAny { invalid.asn1.toRepresentation() }
        val recovered = decodeFrom<kotlinx.serialization.json.JsonObject, AttributeTypeAndValue> {
            Country("AT")
        }(raw)
        recovered.isValid shouldBe true
        J509.attribute(recovered) shouldBeSameInstanceAs raw

        val csr = Json.parseToJsonElement("""{"oid":"1.2.840.113549.1.9.14","extensions":[]}""").jsonObject
        J509.csrAttribute(J509.csrAttribute(csr).shouldBeInstanceOf<InvalidCsrAttribute>()) shouldBeSameInstanceAs csr
    }
}

@Serializable
private data class InvalidPolicyWire(val oid: ObjectIdentifier, val qualifiers: List<InvalidQualifierWire>)
@Serializable
private data class InvalidQualifierWire(val oid: ObjectIdentifier, val value: Asn1Element)
