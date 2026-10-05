package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum

import at.asitplus.awesn1.Asn1String
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.extn.KeyUsage
import at.asitplus.signum.indispensable.pki.extn.UsageBit
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

private inline fun <reified T : Encodable> checkRoundTrip(target: Decodable<T>, source: T): T {
    val bytes = Signum.Der.encodeToByteArray(source)
    val decoded = Signum.Der.decodeFromByteArray<T>(bytes)
    decoded shouldBe source
    Signum.Der.encodeToByteArray(decoded) shouldBe bytes
    requireNotNull(decoded.representations[X509])
    return decoded
}

val PkixEncodingTest by matrixSuite {
    "Concrete extensions use contextual DER and retain their native models" {
        val source = KeyUsage(UsageBit.DIGITAL_SIGNATURE, UsageBit.KEY_CERT_SIGN)
        val decoded = checkRoundTrip(KeyUsage, source)
        decoded.representations[X509] shouldBe decoded.asn1Representation
    }

    "Concrete attributes use contextual DER and retain their native models" {
        val decoded = checkRoundTrip(CommonName, CommonName("round-trip"))
        decoded.representations[X509] shouldBe decoded.asn1Representation
    }

    "Concrete names use contextual DER and retain their native models" {
        val decoded = checkRoundTrip(DNSName, DNSName(Asn1String.IA5("example.com")))
        decoded.representations[X509] shouldBe decoded.asn1Representation
    }
}
