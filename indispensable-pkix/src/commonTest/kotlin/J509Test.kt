@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.attributes.*
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.eygraber.uri.Uri
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.json.*
import kotlin.time.Instant

private val policyOid = ObjectIdentifier("1.2.3.4")
private fun j509Contents(extensions: List<CertificateExtension>) = TbsCertificate(
    serialNumber = BigInteger.ONE,
    signatureAlgorithm = EcdsaAlgorithm.withSHA256,
    issuerName = Name(listOf(RelativeDistinguishedName(CommonName("issuer")))),
    validFrom = Instant.fromEpochSeconds(1_700_000_000),
    validUntil = Instant.fromEpochSeconds(1_800_000_000),
    subjectName = Name(listOf(RelativeDistinguishedName(setOf(CommonName("subject"), Organization("example"))))),
    publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
    extensions = extensions,
)

val J509Test by matrixSuite {
    "Semantic certificate contents traverse JSON, PKIX, ASN.1, and JSON without an ASN.1-shaped JSON payload" {
        val hardware = HardwareModuleName(policyOid, byteArrayOf(1, 2, 3))
        val names = listOf(DNSName("example.com"), RFC822Name("me@example.com"), UriName("https://example.com"),
            IPAddressName.fromString("192.0.2.1"), RegisteredIDName(policyOid), DirectoryName(Name.EMPTY),
            hardware, SmtpUtf8Mailbox("mé@example.test"), MacAddressName(byteArrayOf(0, 1, 2, 3, 4, 5)),
            EDIPartyName("Party"), EDIPartyName("Pärtÿ", "Assigner"))
        val cps = CpsUri(Uri.parse("https://example.com/policy"))
        cps.uri.host shouldBe "example.com"
        cps shouldBe CpsUri("https://example.com/policy")
        val qualifiers = listOf(cps, UserNotice(NoticeReference("Example", listOf(BigInteger.ONE)), "Read this"))
        val source = j509Contents(listOf(
            BasicConstraints(true, 3u), KeyUsage(UsageBit.DIGITAL_SIGNATURE), SubjectKeyIdentifier(byteArrayOf(4, 5)),
            AuthorityKeyIdentifier(byteArrayOf(4, 5), listOf(hardware), BigInteger.TWO), ExtendedKeyUsage(setOf(policyOid)),
            InhibitAnyPolicy(2), PolicyConstraints(1, 2), PolicyMappings(listOf(CertificatePolicyMap(policyOid, ObjectIdentifier("1.2.3.5")))),
            CertificatePolicies(listOf(PolicyInformation(policyOid, qualifiers))),
            NameConstraints(GeneralSubtrees(listOf(GeneralSubtree(DNSName("example.com"))))), SubjectAlternativeName(names),
        ))
        source.sourceFormat shouldBe "<no source>"
        val json = J509.encode(source)
        val decoded = J509.decode(json)
        decoded shouldBe source
        J509.encode(decoded) shouldBe json
        decoded.extensions.all { it.sourceFormat == "JsonObject" } shouldBe true
        decoded.subjectAlternativeNames!!.generalNames shouldBe names
        decoded.subjectName.relativeDistinguishedNames.single().attrsAndValues.first()
            .shouldBeInstanceOf<CommonName>().text shouldBe "subject"

        val der = decoded.asn1.toDer()
        val fromDer = TbsCertificate.fromAsn1(der)
        fromDer shouldBe source
        J509.decode(J509.encode(fromDer)) shouldBe source
        J509.encode(decoded) shouldBe json
        source.sourceFormat shouldBe "<no source>"
    }

    "JSON CSR extension requests expose extensions without converting through DER" {
        val json = Json.parseToJsonElement("""{"oid":"1.2.840.113549.1.9.14","extensions":[{"oid":"1.2.3.999","critical":true,"value":{"native":{"answer":42}}}]}""").jsonObject
        val attribute = J509.csrAttribute(json).shouldBeInstanceOf<ExtensionRequest>()
        val csr = TbsCertificationRequest(Name.EMPTY, ECCurve.SECP_256_R_1.generator.asPublicKey(), attributes = listOf(attribute))
        csr.extensions.single().oid shouldBe ObjectIdentifier("1.2.3.999")
        J509.csrAttribute(attribute) shouldBeSameInstanceAs json
        shouldThrowAny { csr.asn1.toRepresentation() }
        shouldThrowAny { j509Contents(csr.extensions).asn1.toRepresentation() }
    }

    "All four open families preserve native JSON carriers and reject unsupported ASN.1 conversion" {
        val raw = Json.parseToJsonElement("""{"oid":"1.2.3.999","value":{"native":[true,42]},"extra":"preserve me"}""").jsonObject
        val atv = J509.attribute(raw)
        val csr = J509.csrAttribute(raw)
        val name: OtherName = J509.other(raw)
        val qualifier = J509.qualifier(raw)
        listOf(atv.oid, csr.oid, name.oid, qualifier.oid) shouldBe List(4) { ObjectIdentifier("1.2.3.999") }
        J509.attribute(atv) shouldBeSameInstanceAs raw
        J509.csrAttribute(csr) shouldBeSameInstanceAs raw
        J509.other(name) shouldBeSameInstanceAs raw
        J509.qualifier(qualifier) shouldBeSameInstanceAs raw
        listOf(atv, csr, name, qualifier) shouldBe listOf(J509.attribute(raw), J509.csrAttribute(raw), J509.other(raw), J509.qualifier(raw))
        listOf(atv, csr, name, qualifier).forEach { fallback ->
            val shim = fallback.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
            shouldThrow<UnsupportedCryptoException> {
                ServiceLoader.load<GeneralNameFormatProvider>().get<Any, Unit>(fallback) {
                    error("Unknown values must not retry provider lookup")
                }
            } shouldBeSameInstanceAs shim.lookupResult
        }
        val nameShim = name.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
        listOf(true, false).forEach { valid ->
            val validatedName = name.createValidatedCopy { valid }
            validatedName.isValid shouldBe valid
            val validatedShim = validatedName.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
            validatedShim.sourceRepresentation shouldBeSameInstanceAs nameShim.sourceRepresentation
            validatedShim.lookupResult shouldBeSameInstanceAs nameShim.lookupResult
            J509.other(validatedName) shouldBeSameInstanceAs raw
        }
        val nativeNames = j509Contents(listOf(SubjectAlternativeName(listOf(name)), IssuerAlternativeName(listOf(name))))
        nativeNames.subjectAlternativeNames!!.generalNames.single() shouldBeSameInstanceAs name
        nativeNames.issuerAlternativeNames!!.generalNames.single() shouldBeSameInstanceAs name
        shouldThrowAny { atv.asn1.toRepresentation() }
        shouldThrowAny { csr.asn1.toRepresentation() }
        shouldThrowAny { name.asn1.toRepresentation() }
        shouldThrowAny { CertificatePolicies(listOf(PolicyInformation(policyOid, listOf(qualifier)))).asn1.toRepresentation() }
        Name(listOf(RelativeDistinguishedName(atv))).isValid shouldBe true
        shouldThrowAny { Name(listOf(RelativeDistinguishedName(atv))).asn1.toRepresentation() }
    }

    "Semantic copies discard the old JSON source" {
        val original = J509.qualifier(J509.qualifier(UserNotice(explicitText = "before"))).shouldBeInstanceOf<UserNotice>()
        val copy = original.copy(explicitText = "after")
        copy.sourceFormat shouldBe "<no source>"
        J509.qualifier(copy).getValue("value").jsonObject.getValue("text").jsonPrimitive.content shouldBe "after"
        J509.qualifier(original).getValue("value").jsonObject.getValue("text").jsonPrimitive.content shouldBe "before"
    }

    "Malformed ASN.1 otherName retains its decoder failure when validated" {
        val source = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            MacAddressName.OID, Asn1String.UTF8("wrong payload type").encodeToTlv(),
        ))
        val name = OtherName(source)
        val shim = name.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
        shim.lookupResult.cause.shouldNotBeNull()
        val copy = name.createValidatedCopy { true }
        val copyShim = copy.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
        copyShim.lookupResult shouldBeSameInstanceAs shim.lookupResult
        copyShim.sourceRepresentation shouldBeSameInstanceAs shim.sourceRepresentation
        (copy.asn1.toRepresentation() as X509GeneralName.Other).value shouldBeSameInstanceAs source.value
    }

    "Unknown ASN.1 qualifiers remain nested opaque values instead of hiding the whole extension" {
        val body = Signum.Der.encodeToByteArray(kotlinx.serialization.builtins.ListSerializer(UnknownPolicyWire.serializer()),
            listOf(UnknownPolicyWire(policyOid, listOf(UnknownQualifierWire(ObjectIdentifier("1.2.3.999"),
                at.asitplus.awesn1.Asn1String.UTF8("opaque").encodeToTlv())))))
        val ext = CertificateExtension.fromAsn1(at.asitplus.awesn1.crypto.pki.X509CertificateExtension(CertificatePolicies.oid, false, body))
            .shouldBeInstanceOf<CertificatePolicies>()
        ext.certificatePolicies.single().policyQualifiers.single().oid shouldBe ObjectIdentifier("1.2.3.999")
        CertificatePolicies(ext.certificatePolicies).asn1.toRepresentation().value shouldBe body
    }
}

@kotlinx.serialization.Serializable
private data class UnknownPolicyWire(val oid: ObjectIdentifier, val qualifiers: List<UnknownQualifierWire>)
@kotlinx.serialization.Serializable
private data class UnknownQualifierWire(val oid: ObjectIdentifier, val payload: at.asitplus.awesn1.Asn1Element)
