package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.signumX509Serializers
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.extn.KeyUsage
import at.asitplus.signum.indispensable.pki.extn.UsageBit
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.plus

private val pkixDer = DER { serializersModule = signumX509Serializers + signumPkixX509Serializers }

private inline fun <reified T : Encodable> checkRoundTrip(target: Decodable<T>, source: T): T {
    val bytes = pkixDer.encodeToByteArray(source)
    val decoded = pkixDer.decodeFromByteArray<T>(bytes)
    decoded shouldBe source
    pkixDer.encodeToByteArray(decoded) shouldBe bytes
    // Direct concrete dispatch must also be installed on DefaultDer at test-session startup.
    DER.decodeFromByteArray<T>(DER.encodeToByteArray(source)) shouldBe decoded
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
