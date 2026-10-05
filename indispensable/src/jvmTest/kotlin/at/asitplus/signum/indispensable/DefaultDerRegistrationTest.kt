package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum
import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import at.asitplus.signum.indispensable.decodeFromPem

import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.kotest.assertions.throwables.shouldThrowAny
import kotlinx.serialization.modules.SerializersModule
import io.kotest.matchers.shouldBe

val DefaultDerRegistrationTest by matrixSuite {
    "Test session registers Certificate and TbsCertificate once" {
        Signum.Der shouldBeSameInstanceAs DER
        shouldThrowAny { Signum.registerAsn1Serializers(SerializersModule {}) }
        val pem = checkNotNull(Certificate::class.java.getResourceAsStream("/ff/A-Trust-Root-05.crt"))
            .bufferedReader().use { it.readText() }
        val certificate = Signum.Der.decodeFromPem<Certificate>(pem)
        val bytes = Signum.Der.encodeToByteArray(certificate)
        Signum.Der.encodeToByteArray(Signum.Der.decodeFromByteArray<Certificate>(bytes)) shouldBe bytes
        val tbsBytes = Signum.Der.encodeToByteArray(certificate.tbsCertificate)
        Signum.Der.encodeToByteArray(Signum.Der.decodeFromByteArray<TbsCertificate>(tbsBytes)) shouldBe tbsBytes
    }
}
