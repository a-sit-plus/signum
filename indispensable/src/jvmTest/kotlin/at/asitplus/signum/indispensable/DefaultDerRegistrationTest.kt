package at.asitplus.signum.indispensable

import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.modules.SerializersModule

val DefaultDerRegistrationTest by matrixSuite {
    "Test session registers Certificate and TbsCertificate once" {
        Signum.Der shouldBeSameInstanceAs DER
        shouldThrowAny { Signum.registerAsn1Serializers(SerializersModule {}) }
        val pem = checkNotNull(Certificate::class.java.getResourceAsStream("/ff/A-Trust-Root-05.crt"))
            .bufferedReader().use { it.readText() }
        val certificate = Certificate.fromAsn1(pem)
        val bytes = certificate.asn1.toDer()
        Certificate.fromAsn1(bytes).asn1.toDer() shouldBe bytes
        val tbsBytes = certificate.tbsCertificate.asn1.toDer()
        TbsCertificate.fromAsn1(tbsBytes).asn1.toDer() shouldBe tbsBytes
    }
}
