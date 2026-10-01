package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlin.time.Instant

private fun certificate() = Certificate(
    TbsCertificate(
        serialNumber = Asn1Integer.ONE,
        signatureAlgorithm = EcdsaAlgorithm.withSHA256,
        issuerName = X500Name.EMPTY,
        subjectName = X500Name.EMPTY,
        validFrom = Instant.fromEpochSeconds(1_700_000_000),
        validUntil = Instant.fromEpochSeconds(1_800_000_000),
        publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
    ),
    EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO),
)

val CertificateEncodingTest by matrixSuite {
    "Registry dispatch distinguishes Certificate and TbsCertificate" {
        val source = certificate()
        val outer: Encodable = source
        val inner: Encodable = source.tbsCertificate
        val target: Decodable<Certificate> = Certificate
        val bytes = outer.encode(DER)
        bytes shouldNotBe inner.encode(DER)
        val decoded = target.decode(bytes, DER)
        decoded.encode(DER) shouldBe bytes
        decoded.tbsCertificate.encode(DER) shouldBe inner.encode(DER)
        decoded shouldBe source
        decoded.hashCode() shouldBe source.hashCode()
        decoded.asn1Representation shouldBeSameInstanceAs decoded.representations[X509]
        shouldThrowAny { target.decode(bytes, DER { maxInputLength = 1 }) }
    }

    "Retained outer and signed TBS models do not require supported algorithms" {
        val template = certificate().asn1Representation
        val unknown = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null)
        val tbs = X509TbsCertificate(
            version = null,
            serialNumber = template.tbsCertificate.serialNumber,
            signatureAlgorithm = unknown,
            issuerName = template.tbsCertificate.issuerName,
            validFrom = Asn1Time.SecondsCapped(template.tbsCertificate.validity.validFrom.instant),
            validUntil = Asn1Time.SecondsCapped(template.tbsCertificate.validity.validUntil.instant),
            subjectName = template.tbsCertificate.subjectName,
            subjectPublicKeyInfo = template.tbsCertificate.subjectPublicKeyInfo,
        )
        val original = X509Certificate(tbs, unknown, template.signatureValue)
        val bytes = DER.encodeToTlv(original).derEncoded
        val decoded = Certificate.decode(bytes, DER)
        decoded.encode(DER) shouldBe bytes
        decoded.tbsCertificate.encode(DER) shouldBe DER.encodeToTlv(tbs).derEncoded
        Certificate(original).asn1Representation shouldBeSameInstanceAs original
        shouldThrowAny { decoded.signatureAlgorithm }
    }

    "Outer signature algorithm must match the signed TBS algorithm" {
        val source = certificate().asn1Representation
        val mismatched = X509Certificate(
            source.tbsCertificate,
            X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null),
            source.signatureValue,
        )
        shouldThrowAny { Certificate.decode(DER.encodeToTlv(mismatched).derEncoded, DER) }
    }

    "Existing PEM helpers use the certificate codec and respect input limits" {
        val source = certificate()
        val pem = source.encodeToPem()
        Certificate.decodeFromPem(pem) shouldBe source
        shouldThrowAny { Certificate.decodeFromPem(pem, limit = 1) }
        shouldThrowAny { Certificate.decodeFromPem(pem, der = DER { maxInputLength = 1 }) }
    }
}
