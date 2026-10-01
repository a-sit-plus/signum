package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlin.time.Instant

private object ExtraRepresentation : Encodable.Representation

private fun tbsCertificate(
    validFrom: Instant = Instant.fromEpochSeconds(1_700_000_000),
    subjectName: Name = X500Name.EMPTY,
) = TbsCertificate(
    serialNumber = Asn1Integer.ONE,
    signatureAlgorithm = EcdsaAlgorithm.withSHA256,
    issuerName = X500Name.EMPTY,
    subjectName = subjectName,
    validFrom = validFrom,
    validUntil = Instant.fromEpochSeconds(1_800_000_000),
    publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
    representations = mapOf(ExtraRepresentation to "metadata"),
)

val TbsCertificateEncodingTest by matrixSuite {
    "Default codec dispatch and retained original" {
        val source = tbsCertificate()
        val value: Encodable = source
        val target: Decodable<TbsCertificate> = TbsCertificate
        val bytes = value.encode(DER)
        val decoded = target.decode(bytes, DER)
        decoded.encode(DER) shouldBe bytes
        decoded shouldBe source
        decoded.hashCode() shouldBe source.hashCode()
        decoded.asn1Representation shouldBeSameInstanceAs decoded.representations[X509]
        val original = source.asn1Representation
        TbsCertificate(original).asn1Representation shouldBeSameInstanceAs original
        shouldThrowAny { target.decode(bytes, DER { maxInputLength = 1 }) }
    }

    "Unsupported original algorithms can round-trip without semantic decoding" {
        val template = tbsCertificate().asn1Representation
        val original = X509TbsCertificate(
            serialNumber = template.serialNumber,
            signatureAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null),
            issuerName = template.issuerName,
            validFrom = Asn1Time.SecondsCapped(template.validity.validFrom.instant),
            validUntil = Asn1Time.SecondsCapped(template.validity.validUntil.instant),
            subjectName = template.subjectName,
            subjectPublicKeyInfo = template.subjectPublicKeyInfo,
        )
        val bytes = DER.encodeToTlv(original).derEncoded
        val decoded = TbsCertificate.decode(bytes, DER)
        decoded.encode(DER) shouldBe bytes
        shouldThrowAny { decoded.signatureAlgorithm }
    }

    "Semantic precision and unsupported names are independent of DER" {
        val fractional = Instant.fromEpochSeconds(1_700_000_000, 123)
        val source = tbsCertificate(fractional)
        source.validFrom shouldBe fractional
        TbsCertificate.decode(source.encode(DER), DER) shouldNotBe source
        val unsupported = object : Name {
            override val relativeDistinguishedNames = emptyList<RelativeDistinguishedName>()
        }
        val value = tbsCertificate(subjectName = unsupported)
        value.subjectName shouldBeSameInstanceAs unsupported
        shouldThrowAny { value.encode(DER) }
    }
}
