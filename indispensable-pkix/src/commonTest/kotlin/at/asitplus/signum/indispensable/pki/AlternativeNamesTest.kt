package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray

import at.asitplus.signum.indispensable.pki.attributes.*

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.subjectAltName_2_5_29_17
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.signum.indispensable.pki.x500.DirectoryName
import at.asitplus.signum.indispensable.pki.x500.RegisteredIDName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

private fun serializer() = X509GeneralNames.serializer()

private fun List<GeneralName>.tags() = map { it.tag }

val AlternativeNamesTest by matrixSuite {
    Signum.installPkix()

    test("Generic and typed names agree on equality and hash codes") {
        val typed: GeneralName = DNSName(Asn1String.IA5("example.com"))
        val generic: GeneralName = BaseX509GeneralName(X509GeneralName.Dns("example.com"))
        typed shouldBe generic
        generic shouldBe typed
        typed.hashCode() shouldBe generic.hashCode()
        setOf(typed, generic).size shouldBe 1
    }

    // Kotlin-built names must encode with the proper GeneralName CHOICE tags (implicit [n] for the
    // primitives, explicit [4] for the directoryName/X500Name) so they decode back — the regression
    // this guards against produced untagged universal elements that failed to re-decode.
    test("Kotlin-built alternative names round-trip through X509GeneralNames") {
        val generalNames = listOf(
            DNSName(Asn1String.IA5("example.com")),
            RegisteredIDName(ObjectIdentifier("1.2.3.4")),
            DirectoryName(X500Name(RelativeDistinguishedName(CommonName("Directory")))),
        )

        val built = AlternativeNames.fromGeneralNames(generalNames)
        val encoded = built.let { Signum.Der.encodeToByteArray(it) }
        val decoded = Signum.Der.decodeFromByteArray<AlternativeNames>(encoded)

        decoded.generalNames.tags() shouldBe listOf(
            X509GeneralName.Tags.dnsName, X509GeneralName.Tags.registeredID, X509GeneralName.Tags.directoryName,
        )
        (decoded.generalNames[2] as DirectoryName).name.toRfc2253String() shouldBe "cn=directory" // RFC 2253 canonical: type + value lower-cased
        decoded.let { Signum.Der.encodeToByteArray(it) } shouldBe encoded
    }

    test("asn1-built alternative names preserve original DER") {
        val encoded = byteArrayOf(
            0x30, 0x18,
            0x82.toByte(), 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // [2] example.com
            0x87.toByte(), 0x04, 0x7f, 0x00, 0x00, 0x01,                                            // [7] 127.0.0.1
            0x88.toByte(), 0x03, 0x2a, 0x03, 0x04,                                                  // [8] 1.2.3.4
        )
        val decoded = Signum.Der.decodeFromTlv<AlternativeNames>(Asn1Element.parse(encoded))

        decoded.generalNames.tags() shouldBe listOf(
            X509GeneralName.Tags.dnsName, X509GeneralName.Tags.ipAddress, X509GeneralName.Tags.registeredID,
        )
        decoded.let { Signum.Der.encodeToByteArray(it) } shouldBe encoded
    }

    test("duplicate subject alternative name extension rejected") {
        val encoded = AlternativeNames
            .fromGeneralNames(listOf(DNSName(Asn1String.IA5("example.com"))))
            .let { Signum.Der.encodeToByteArray(it) }
        val extensions = listOf(
            CertificateExtension(KnownOIDs.subjectAltName_2_5_29_17, value = encoded),
            CertificateExtension(KnownOIDs.subjectAltName_2_5_29_17, value = encoded),
        )

        shouldThrow<Asn1Exception> {
            with(AlternativeNames) { extensions.findSubjectAltNames() }
        }
    }
}
