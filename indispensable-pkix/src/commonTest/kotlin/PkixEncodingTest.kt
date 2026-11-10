package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.sourceFormat
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeTo

import at.asitplus.signum.Signum

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.Asn1Sequence
import io.kotest.matchers.types.shouldBeSameInstanceAs
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

private data class OtherConstraintsRepresentation(val ca: Boolean)

private inline fun <reified T : at.asitplus.signum.indispensable.WithSourceRepresentation> checkRoundTrip(source: T): T {
    source.sourceFormat shouldBe "<no source>"
    val bytes = Signum.Der.encodeToByteArray(source)
    source.sourceFormat shouldBe "<no source>"
    val decoded = Signum.Der.decodeFromByteArray<T>(bytes)
    decoded shouldBe source
    Signum.Der.encodeToByteArray(decoded) shouldBe bytes
    return decoded
}

val PkixEncodingTest by matrixSuite {
    "A different source representation converts through the ASN.1 provider without being replaced" {
        val original = OtherConstraintsRepresentation(true)
        val semantic = decodeFrom<OtherConstraintsRepresentation, BasicConstraints> { BasicConstraints(it.ca) }(original)
        CertificateExtension.fromAsn1(semantic.asn1.toRepresentation()) shouldBe BasicConstraints(true)
        semantic.encodeTo<OtherConstraintsRepresentation, BasicConstraints> {
            error("The original representation should be retained")
        } shouldBeSameInstanceAs original
    }

    "Copying a decoded extension encodes the new fields instead of the original source" {
        val decoded = CertificateExtension.fromAsn1(BasicConstraints(true, 3u).asn1.toRepresentation()) as BasicConstraints
        val copy = decoded.copy(ca = false, pathLenConstraint = null)
        copy.sourceFormat shouldBe "<no source>"
        CertificateExtension.fromAsn1(copy.asn1.toRepresentation()) shouldBe BasicConstraints(false)
        decoded.pathLenConstraint shouldBe 3u
    }

    "Copying a decoded subtree constructs semantics without retaining its old source" {
        val decoded = checkRoundTrip(GeneralSubtree(DNSName(Asn1String.IA5("example.com"))))
        val copy = decoded.copy(minimum = com.ionspin.kotlin.bignum.integer.BigInteger.ONE)
        copy.sourceFormat shouldBe "<no source>"
        val roundTripped = Signum.Der.decodeFromByteArray<GeneralSubtree>(Signum.Der.encodeToByteArray(copy))
        roundTripped.minimum shouldBe com.ionspin.kotlin.bignum.integer.BigInteger.ONE
        decoded.sourceFormat shouldBe "X509GeneralSubtree"
    }

    "Programmatic PKIX extensions retain no source before or after encoding" {
        val extensions = listOf(
            KeyUsage(UsageBit.DIGITAL_SIGNATURE), BasicConstraints(true),
            ExtendedKeyUsage(setOf(ObjectIdentifier("1.2.3.4"))),
            SubjectKeyIdentifier(byteArrayOf(1, 2)), AuthorityKeyIdentifier(byteArrayOf(1, 2)),
            InhibitAnyPolicy(1), PolicyConstraints(requireExplicitPolicy = 1),
            PolicyMappings(emptyList()), CertificatePolicies(emptyList()), NameConstraints(),
        )
        extensions.forEach { source ->
            source.sourceFormat shouldBe "<no source>"
            val original = source.asn1.toRepresentation()
            val decoded = CertificateExtension.fromAsn1(original)
            decoded.asn1.toRepresentation() shouldBeSameInstanceAs original
            Signum.Der.encodeToByteArray<CertificateExtension>(source) shouldBe
                Signum.Der.encodeToByteArray<CertificateExtension>(decoded)
            source.sourceFormat shouldBe "<no source>"
        }
    }

    "Programmatic names encode through the base interface without acquiring a source" {
        val names = listOf(
            DNSName(Asn1String.IA5("example.com")), RFC822Name(Asn1String.IA5("me@example.com")),
            UriName("https://example.com"), RegisteredIDName(ObjectIdentifier("1.2.3.4")),
            DirectoryName(Name.EMPTY), IPAddressName.fromString("192.0.2.1"),
            IPAddressName.fromString("192.0.2.0/24"), IPAddressName.fromString("2001:db8::1"),
            EDIPartyName(Asn1Sequence(emptyList())), X400AddressName(Asn1Sequence(emptyList())),
        )
        names.forEach { source ->
            source.sourceFormat shouldBe "<no source>"
            val original = requireNotNull((source as GeneralName).asn1.toRepresentation())
            val decoded = GeneralName.fromAsn1(original)
            decoded.asn1.toRepresentation() shouldBeSameInstanceAs original
            Signum.Der.encodeToByteArray<GeneralName>(source) shouldBe
                Signum.Der.encodeToByteArray<GeneralName>(decoded)
            source.sourceFormat shouldBe "<no source>"
        }
    }

    "Concrete extensions use contextual DER and retain their native models" {
        val source = KeyUsage(UsageBit.DIGITAL_SIGNATURE, UsageBit.KEY_CERT_SIGN)
        val decoded = checkRoundTrip(source)
        decoded.asn1.toRepresentation() shouldBeSameInstanceAs decoded.asn1.toRepresentation()
    }

    "Concrete attributes use contextual DER and retain their native models" {
        val decoded = checkRoundTrip(CommonName("round-trip"))
        decoded.asn1.toRepresentation() shouldBeSameInstanceAs decoded.asn1.toRepresentation()
        val value = Asn1String.Printable("round-trip").encodeToTlv()
        val constructed = AttributeTypeAndValue(CommonName.oid, value) as CommonName
        constructed.sourceFormat shouldBe "X500AttributeTypeAndValue"
        constructed.asn1.toRepresentation().value shouldBeSameInstanceAs value
    }

    "Concrete names use contextual DER and retain their native models" {
        val decoded = checkRoundTrip(DNSName(Asn1String.IA5("example.com")))
        decoded.asn1.toRepresentation() shouldBeSameInstanceAs decoded.asn1.toRepresentation()
    }
}
