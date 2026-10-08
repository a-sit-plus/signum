package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.sourceRepresentationFor
import at.asitplus.signum.Signum

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.Asn1Sequence
import io.kotest.matchers.types.shouldBeSameInstanceAs
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

private inline fun <reified T : Encodable> checkRoundTrip(target: Decodable<T>, source: T): T {
    source.sourceRepresentation shouldBe null
    val bytes = Signum.Der.encodeToByteArray(source)
    source.sourceRepresentation shouldBe null
    val decoded = Signum.Der.decodeFromByteArray<T>(bytes)
    decoded shouldBe source
    Signum.Der.encodeToByteArray(decoded) shouldBe bytes
    decoded.sourceRepresentation?.first shouldBe X509
    requireNotNull(decoded.sourceRepresentationFor(X509))
    return decoded
}

val PkixEncodingTest by matrixSuite {
    "Copying a decoded subtree constructs semantics without retaining its old source" {
        val decoded = checkRoundTrip(GeneralSubtree, GeneralSubtree(DNSName(Asn1String.IA5("example.com"))))
        val copy = decoded.copy(minimum = Asn1Integer(1))
        copy.sourceRepresentation shouldBe null
        val roundTripped = Signum.Der.decodeFromByteArray<GeneralSubtree>(Signum.Der.encodeToByteArray(copy))
        roundTripped.minimum shouldBe Asn1Integer(1)
        decoded.sourceRepresentation?.first shouldBe X509
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
            source.sourceRepresentation shouldBe null
            val original = source.asn1Representation
            val decoded = CertificateExtension.fromAsn1Representation(original)
            decoded.sourceRepresentation?.second shouldBeSameInstanceAs original
            Signum.Der.encodeToByteArray<CertificateExtension>(source) shouldBe
                Signum.Der.encodeToByteArray<CertificateExtension>(decoded)
            source.sourceRepresentation shouldBe null
        }
    }

    "Programmatic names encode through the base interface without acquiring a source" {
        val names = listOf(
            DNSName(Asn1String.IA5("example.com")), RFC822Name(Asn1String.IA5("me@example.com")),
            UriName("https://example.com"), RegisteredIDName(ObjectIdentifier("1.2.3.4")),
            DirectoryName(X500Name.EMPTY), IPAddressName.fromString("192.0.2.1"),
            IPAddressName.fromString("192.0.2.0/24"), IPAddressName.fromString("2001:db8::1"),
            EDIPartyName(Asn1Sequence(emptyList())), X400AddressName(Asn1Sequence(emptyList())),
        )
        names.forEach { source ->
            source.sourceRepresentation shouldBe null
            val original = requireNotNull((source as GeneralName).asn1Representation)
            val decoded = GeneralName.fromAsn1Representation(original)
            decoded.sourceRepresentation?.second shouldBeSameInstanceAs original
            Signum.Der.encodeToByteArray<GeneralName>(source) shouldBe
                Signum.Der.encodeToByteArray<GeneralName>(decoded)
            source.sourceRepresentation shouldBe null
        }
    }

    "Concrete extensions use contextual DER and retain their native models" {
        val source = KeyUsage(UsageBit.DIGITAL_SIGNATURE, UsageBit.KEY_CERT_SIGN)
        val decoded = checkRoundTrip(KeyUsage, source)
        decoded.sourceRepresentationFor(X509) shouldBe decoded.asn1Representation
    }

    "Concrete attributes use contextual DER and retain their native models" {
        val decoded = checkRoundTrip(CommonName, CommonName("round-trip"))
        decoded.sourceRepresentationFor(X509) shouldBe decoded.asn1Representation
        val value = Asn1String.Printable("round-trip").encodeToTlv()
        val constructed = AttributeTypeAndValue(CommonName.oid, value) as CommonName
        constructed.sourceRepresentation shouldBe null
        constructed.asn1Representation.value shouldBeSameInstanceAs value
    }

    "Concrete names use contextual DER and retain their native models" {
        val decoded = checkRoundTrip(DNSName, DNSName(Asn1String.IA5("example.com")))
        decoded.sourceRepresentationFor(X509) shouldBe decoded.asn1Representation
    }
}
