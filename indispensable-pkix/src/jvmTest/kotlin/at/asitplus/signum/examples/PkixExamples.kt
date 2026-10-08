package at.asitplus.signum.examples

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

val PkixExamples by matrixSuite {
    "typed extensions, attributes and general names" {
        // --8<-- [start:pkix-typed-data]
        val usage = KeyUsage(UsageBit.DIGITAL_SIGNATURE)
        val decoded = Signum.Der.decodeFromByteArray<CertificateExtension>(
            Signum.Der.encodeToByteArray<CertificateExtension>(usage))
        decoded shouldBe usage
        (decoded is KeyUsage) shouldBe true /* (1)! */
        val name = CommonName("client")
        Signum.Der.decodeFromByteArray<CommonName>(Signum.Der.encodeToByteArray(name)) shouldBe name
        val dns = DNSName(Asn1String.IA5("example.com"))
        Signum.Der.decodeFromByteArray<DNSName>(Signum.Der.encodeToByteArray(dns)) shouldBe dns
        // --8<-- [end:pkix-typed-data]
    }
    "unknown extensions are preserved but malformed registered data fails" {
        // --8<-- [start:pkix-unknown-malformed]
        val unknown = CertificateExtension(ObjectIdentifier("1.3.6.1.4.1.55555.99"), value = byteArrayOf(1, 2))
        val decoded = Signum.Der.decodeFromByteArray<CertificateExtension>(Signum.Der.encodeToByteArray(unknown))
        decoded.oid shouldBe unknown.oid
        val malformed = CertificateExtension(BasicConstraints.oid, value = byteArrayOf(1, 2))
        runCatching {
            Signum.Der.decodeFromByteArray<CertificateExtension>(Signum.Der.encodeToByteArray(malformed))
        }.isFailure shouldBe true
        // --8<-- [end:pkix-unknown-malformed]
    }

}
