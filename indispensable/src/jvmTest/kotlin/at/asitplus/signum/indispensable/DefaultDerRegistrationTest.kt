package at.asitplus.signum.indispensable

import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

val DefaultDerRegistrationTest by matrixSuite {
    "Test session registers Certificate and TbsCertificate once" {
        val pem = checkNotNull(Certificate::class.java.getResourceAsStream("/ff/A-Trust-Root-05.crt"))
            .bufferedReader().use { it.readText() }
        val certificate = Certificate.decodeFromPem(pem)
        val bytes = DER.encodeToByteArray(certificate)
        DER.encodeToByteArray(DER.decodeFromByteArray<Certificate>(bytes)) shouldBe bytes
        val tbsBytes = DER.encodeToByteArray(certificate.tbsCertificate)
        DER.encodeToByteArray(DER.decodeFromByteArray<TbsCertificate>(tbsBytes)) shouldBe tbsBytes
    }
}
