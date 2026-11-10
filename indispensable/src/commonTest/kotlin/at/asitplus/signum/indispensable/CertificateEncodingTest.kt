package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Instant

private fun certificate() = Certificate(
    TbsCertificate(
        serialNumber = BigInteger.ONE,
        signatureAlgorithm = EcdsaAlgorithm.withSHA256,
        issuerName = Name.EMPTY,
        subjectName = Name.EMPTY,
        validFrom = Instant.fromEpochSeconds(1_700_000_000),
        validUntil = Instant.fromEpochSeconds(1_800_000_000),
        publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
    ),
    EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO),
)

val CertificateEncodingTest by matrixSuite {

    "Retained outer and signed TBS models do not require supported algorithms" {
        val template = certificate().toAsn1()
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
        val bytes = Signum.Der.encodeToByteArray(original)
        val decoded = Certificate.fromAsn1(bytes)
        decoded.asn1.toDer() shouldBe bytes
        decoded.tbsCertificate.asn1.toDer() shouldBe Signum.Der.encodeToByteArray(tbs)
        Certificate.fromAsn1(original).toAsn1()  shouldBeSameInstanceAs original
        shouldThrow<UnsupportedCryptoException> { decoded.signature }
    }

    "Outer signature algorithm must match the signed TBS algorithm" {
        val source = certificate().toAsn1()
        val mismatched = X509Certificate(
            source.tbsCertificate,
            X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null),
            source.signatureValue,
        )
        shouldThrowAny { Certificate.fromAsn1(mismatched) }
    }

    "Existing PEM helpers use the certificate bridge" {
        val source = certificate()
        val pem = source.asn1.toPem()
        Certificate.fromAsn1(pem) shouldBe source
    }
}
