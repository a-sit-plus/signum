package at.asitplus.signum.indispensable
import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import at.asitplus.signum.indispensable.decodeFromPem

import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val DefaultDerRegistrationTest by matrixSuite {
    "Test session registers Certificate and TbsCertificate once" {
        val pem = checkNotNull(Certificate::class.java.getResourceAsStream("/ff/A-Trust-Root-05.crt"))
            .bufferedReader().use { it.readText() }
        val certificate = DER.decodeFromPem<Certificate>(pem)
        val bytes = DER.encodeToByteArray(certificate)
        DER.encodeToByteArray(DER.decodeFromByteArray<Certificate>(bytes)) shouldBe bytes
        val tbsBytes = DER.encodeToByteArray(certificate.tbsCertificate)
        DER.encodeToByteArray(DER.decodeFromByteArray<TbsCertificate>(tbsBytes)) shouldBe tbsBytes
    }
}
