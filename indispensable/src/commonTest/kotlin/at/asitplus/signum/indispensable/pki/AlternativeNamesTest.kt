package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.decodeFromDer
import at.asitplus.signum.indispensable.encodeToDer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val AlternativeNamesTest by testSuite {

    test("property-built alternative names round-trip through X509GeneralNames") {
        val directoryName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName("Directory")))
        val ipAddress = byteArrayOf(127, 0, 0, 1)
        val registeredId = ObjectIdentifier("1.2.3.4")
        val names = AlternativeNames(
            dnsNames = listOf("example.com"),
            rfc822Names = listOf("mail@example.com"),
            uris = listOf("https://example.com"),
            ipAddresses = listOf(ipAddress),
            directoryNames = listOf(directoryName),
            registeredIDs = listOf(registeredId),
        )

        val encoded = names.encodeToDer(X509GeneralNames.serializer())
        val decoded = AlternativeNames.decodeFromDer(X509GeneralNames.serializer(), encoded)

        decoded.dnsNames shouldBe listOf("example.com")
        decoded.rfc822Names shouldBe listOf("mail@example.com")
        decoded.uris shouldBe listOf("https://example.com")
        decoded.ipAddresses.single().contentEquals(ipAddress) shouldBe true
        decoded.directoryNames shouldBe listOf(directoryName)
        decoded.registeredIDs shouldBe listOf(registeredId)
        decoded.encodeToDer(X509GeneralNames.serializer()) shouldBe encoded
    }

    test("asn1-built alternative names preserve original DER") {
        val encoded = byteArrayOf(
            0x30, 0x18,
            0x82.toByte(), 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
            0x87.toByte(), 0x04, 0x7f, 0x00, 0x00, 0x01,
            0x88.toByte(), 0x03, 0x2a, 0x03, 0x04,
        )
        val decoded = AlternativeNames.decodeFromTlv(
            X509GeneralNames.serializer(),
            Asn1Element.parse(encoded),
        )

        decoded.dnsNames shouldBe listOf("example.com")
        decoded.ipAddresses.single().contentEquals(byteArrayOf(127, 0, 0, 1)) shouldBe true
        decoded.registeredIDs shouldBe listOf(ObjectIdentifier("1.2.3.4"))
        decoded.encodeToDer(X509GeneralNames.serializer()) shouldBe encoded
    }

    test("duplicate subject alternative name extension rejected") {
        val encoded = AlternativeNames(dnsNames = listOf("example.com"))
            .encodeToDer(X509GeneralNames.serializer())
        val extensions = listOf(
            CertificateExtension(KnownOIDs.subjectAltName_2_5_29_17, value = encoded),
            CertificateExtension(KnownOIDs.subjectAltName_2_5_29_17, value = encoded),
        )

        shouldThrow<Asn1Exception> {
            with(AlternativeNames) { extensions.findSubjectAltNames() }
        }
    }
}
