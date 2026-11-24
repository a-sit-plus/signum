@file:OptIn(at.asitplus.signum.SignumInternals::class)

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
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

val UnknownPkixValueTest by matrixSuite {
    "Basic constraint invariants reject construction and preserve malformed decoded sources" {
        shouldThrowAny { BasicConstraints(ca = false, pathLenConstraint = 0u) }
        shouldThrowAny { PolicyConstraints(requireExplicitPolicy = -1) }
        shouldThrowAny { PolicyConstraints(inhibitPolicyMapping = -1) }
        shouldThrowAny { InhibitAnyPolicy(-1) }

        listOf(
            X509CertificateExtension(BasicConstraints.oid, true, "3003020100".hexToByteArray()),
            X509CertificateExtension(PolicyConstraints.oid, true, "30038001ff".hexToByteArray()),
            X509CertificateExtension(PolicyConstraints.oid, true, "30038101ff".hexToByteArray()),
            X509CertificateExtension(InhibitAnyPolicy.oid, true, "0201ff".hexToByteArray()),
        ).forEach { source ->
            val value = CertificateExtension.fromAsn1(source).shouldBeInstanceOf<CertificateExtension.Unknown>()
            value.lookupResult.suppressedExceptions.isNotEmpty() shouldBe true
            value.oid shouldBe source.oid
            value.asn1.toRepresentation() shouldBeSameInstanceAs source
        }
    }

    "A parseable extension request retains malformed extension payloads as unknowns" {
        val extension = X509CertificateExtension(BasicConstraints.oid, true, "3003020100".hexToByteArray())
        val source = Pkcs10CsrAttribute.ExtensionRequest(listOf(extension))
        val request = CsrAttribute.fromAsn1(source).shouldBeInstanceOf<ExtensionRequest>()
        val fallback = request.extensions.single().shouldBeInstanceOf<CertificateExtension.Unknown>()
        fallback.oid shouldBe BasicConstraints.oid
        fallback.critical shouldBe true
        fallback.lookupResult.suppressedExceptions.isNotEmpty() shouldBe true
        fallback.asn1.toRepresentation().value shouldBe extension.value

        val csr = TbsCertificationRequest(Name.EMPTY, ECCurve.SECP_256_R_1.generator.asPublicKey(), attributes = listOf(request))
        csr.extensions shouldBeSameInstanceAs request.extensions
        val bytes = csr.asn1.toDer()
        val decoded = TbsCertificationRequest.fromAsn1(bytes)
        decoded.extensions.single().shouldBeInstanceOf<CertificateExtension.Unknown>()
            .asn1.toRepresentation().value shouldBe extension.value
        decoded.asn1.toDer() shouldBe bytes
    }

    "Malformed recognized names fall back to unknowns and retain their original source" {
        val sources = listOf<X509GeneralName>(
            X509GeneralName.Dns("bad name"), X509GeneralName.Rfc822("two@@example.com"),
            X509GeneralName.UniformResourceIdentifier(""),
            Signum.Der.decodeFromByteArray(X509GeneralName.serializer(), "870101".hexToByteArray()),
            X509GeneralName.EdiParty(emptyList()),
        )
        sources.forEach { source ->
            val name = GeneralName.fromAsn1(source).shouldBeInstanceOf<GeneralName.Unknown>()
            name.lookupResult.suppressedExceptions.isNotEmpty() shouldBe true
            name.asn1.toRepresentation() shouldBeSameInstanceAs source
            GeneralName.fromAsn1(name.asn1.toDer()).shouldBeInstanceOf<GeneralName.Unknown>()
        }
    }

    "Undecodable ATVs survive as unknowns through name and certificate construction and parsing" {
        val sources = listOf(
            X500AttributeTypeAndValue(CommonName.oid, Asn1Integer(1).encodeToTlv()),
            X500AttributeTypeAndValue(CommonName.oid, Asn1Element.parse("1E0100".hexToByteArray())),
        )
        sources.forEach { source ->
            val atv = AttributeTypeAndValue.fromAsn1(source).also { it.shouldBeInstanceOf<ServiceLoader.UnknownShim>() }
            (atv as ServiceLoader.UnknownShim).lookupResult.suppressedExceptions.isNotEmpty() shouldBe true
            atv.oid shouldBe source.oid
            atv.asn1.toRepresentation() shouldBeSameInstanceAs source
            val name = Name(listOf(RelativeDistinguishedName(atv)))
            Name.fromAsn1(name.asn1.toDer()).relativeDistinguishedNames.single().attrsAndValues.single()
                .also { it.shouldBeInstanceOf<ServiceLoader.UnknownShim>() }
            val contents = TbsCertificate(
                com.ionspin.kotlin.bignum.integer.BigInteger.ONE,
                at.asitplus.signum.indispensable.sign.EcdsaAlgorithm.withSHA256,
                name, kotlin.time.Instant.fromEpochSeconds(1), kotlin.time.Instant.fromEpochSeconds(2), name,
                ECCurve.SECP_256_R_1.generator.asPublicKey(),
            )
            TbsCertificate.fromAsn1(contents.asn1.toDer()).subjectName.relativeDistinguishedNames.single()
                .attrsAndValues.single().also { it.shouldBeInstanceOf<ServiceLoader.UnknownShim>() }
        }
        val unknown = AttributeTypeAndValue.fromAsn1(
            X500AttributeTypeAndValue(ObjectIdentifier("1.2.3.999"), Asn1Integer(1).encodeToTlv())
        )
        unknown.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
        shouldThrowAny { RelativeDistinguishedName(emptySet()) }
    }

    "Malformed known CSR attributes and OtherNames fall back to unknown carriers" {
        val csrSource = Pkcs10CsrAttribute(CsrAttribute.EXTENSION_REQUEST_OID, setOf(Asn1Integer(1).encodeToTlv()))
        val csr = CsrAttribute.fromAsn1(csrSource).also { it.shouldBeInstanceOf<ServiceLoader.UnknownShim>() }
        (csr as ServiceLoader.UnknownShim).lookupResult.suppressedExceptions.isNotEmpty() shouldBe true
        csr.asn1.toRepresentation() shouldBeSameInstanceAs csrSource
        CsrAttribute.fromAsn1(csr.asn1.toDer()).also { it.shouldBeInstanceOf<ServiceLoader.UnknownShim>() }
        CsrAttribute(ObjectIdentifier("1.2.3.999"), Asn1Integer(1).encodeToTlv())
            .shouldBeInstanceOf<ServiceLoader.UnknownShim>()

        val otherSource = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            MacAddressName.OID, Asn1String.UTF8("wrong type").encodeToTlv(),
        ))
        val other = OtherName(otherSource)
        other.shouldBeInstanceOf<OtherName.Unknown>()
        other.oid shouldBe MacAddressName.OID
        (other.asn1.toRepresentation() as X509GeneralName.Other).value shouldBeSameInstanceAs otherSource.value
        val unknownOid = ObjectIdentifier("1.2.3.999")
        val uninterpreted = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            unknownOid, Asn1Integer(1).encodeToTlv(),
        ))
        val unknown = GeneralName.fromAsn1(uninterpreted).shouldBeInstanceOf<OtherName.Unknown>()
        unknown.oid shouldBe unknownOid
        (unknown.asn1.toRepresentation() as X509GeneralName.Other).value shouldBeSameInstanceAs uninterpreted.value
    }

    "Malformed qualifiers stay as unknowns inside interpreted certificate policies" {
        val oid = ObjectIdentifier("1.2.3.4")
        val body = Signum.Der.encodeToByteArray(ListSerializer(FallbackPolicyWire.serializer()), listOf(
            FallbackPolicyWire(oid, listOf(FallbackQualifierWire(CpsUri("").oid, Asn1Integer(1).encodeToTlv()))),
        ))
        val policies = CertificateExtension.fromAsn1(X509CertificateExtension(CertificatePolicies.oid, false, body))
            .shouldBeInstanceOf<CertificatePolicies>()
        val qualifier = policies.certificatePolicies.single().policyQualifiers.single()
            .shouldBeInstanceOf<PolicyQualifierInfo.Unknown>()
        qualifier.lookupResult.suppressedExceptions.isNotEmpty() shouldBe true
        CertificatePolicies(policies.certificatePolicies).asn1.toRepresentation().value shouldBe body
    }

    "Unknown CSR attributes and policy qualifiers distinguish OIDs with identical payloads" {
        val first = ObjectIdentifier("1.2.3.4")
        val second = ObjectIdentifier("1.2.3.5")
        val payload = Asn1Integer(1).encodeToTlv()
        val attribute = CsrAttribute(first, payload).shouldBeInstanceOf<CsrAttribute.Unknown>()
        attribute shouldBe CsrAttribute(first, payload)
        attribute shouldNotBe CsrAttribute(second, payload)

        val failure = at.asitplus.signum.UnsupportedCryptoException()
        val qualifier = PolicyQualifierInfo.Unknown(first, payload, failure)
        qualifier shouldBe PolicyQualifierInfo.Unknown(first, payload, failure)
        qualifier shouldNotBe PolicyQualifierInfo.Unknown(second, payload, failure)
    }

    "Custom values retain a non-ASN.1 source for independent recovery" {
        val raw = Json.parseToJsonElement("""{"oid":"2.5.4.6","value":{"uninterpreted":true},"extra":42}""").jsonObject
        val unknown = J509.attribute(raw)
        J509.attribute(unknown) shouldBeSameInstanceAs raw
        shouldThrowAny { unknown.asn1.toRepresentation() }
        val recovered = decodeFrom<kotlinx.serialization.json.JsonObject, AttributeTypeAndValue> {
            Country("AT")
        }(raw)
        J509.attribute(recovered) shouldBeSameInstanceAs raw

        val csr = Json.parseToJsonElement("""{"oid":"1.2.840.113549.1.9.14","extensions":[]}""").jsonObject
        J509.csrAttribute(J509.csrAttribute(csr)) shouldBeSameInstanceAs csr
    }
}

@Serializable
internal data class FallbackPolicyWire(val oid: ObjectIdentifier, val qualifiers: List<FallbackQualifierWire>)
@Serializable
internal data class FallbackQualifierWire(val oid: ObjectIdentifier, val value: Asn1Element)
