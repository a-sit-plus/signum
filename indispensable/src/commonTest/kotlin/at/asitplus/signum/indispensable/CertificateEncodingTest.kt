package at.asitplus.signum.indispensable
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.encodeToPem

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.io.encodeToSink
import at.asitplus.awesn1.io.decodeFromSource
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
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

private val certificateDer = DER { serializersModule = signumX509Serializers }

val CertificateEncodingTest by matrixSuite {
    "Contextual serializers distinguish Certificate and TbsCertificate" {
        val source = certificate()
        val outer = source
        val inner = source.tbsCertificate
        val bytes = certificateDer.encodeToByteArray(outer)
        bytes shouldNotBe certificateDer.encodeToByteArray(inner)
        val decoded = certificateDer.decodeFromByteArray<Certificate>(bytes)
        certificateDer.encodeToByteArray(decoded) shouldBe bytes
        certificateDer.encodeToByteArray(decoded.tbsCertificate) shouldBe certificateDer.encodeToByteArray(inner)
        decoded shouldBe source
        decoded.hashCode() shouldBe source.hashCode()
        val tlv = certificateDer.encodeToTlv(source)
        tlv.derEncoded shouldBe bytes
        certificateDer.decodeFromTlv<Certificate>(tlv) shouldBe source
        val buffer = Buffer()
        certificateDer.encodeToSink(source, buffer)
        buffer.peek().readByteArray() shouldBe bytes
        certificateDer.decodeFromSource<Certificate>(buffer) shouldBe source
        shouldThrowAny { certificateDer.decodeFromSource<Certificate>(Buffer().apply { write(bytes) }, limit = 1) }
        decoded.asn1Representation shouldBeSameInstanceAs decoded.representations[X509]
        shouldThrowAny { DER { serializersModule = signumX509Serializers; maxInputLength = 1 }.decodeFromByteArray<Certificate>(bytes) }
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
        val decoded = certificateDer.decodeFromByteArray<Certificate>(bytes)
        certificateDer.encodeToByteArray(decoded) shouldBe bytes
        certificateDer.encodeToByteArray(decoded.tbsCertificate) shouldBe DER.encodeToTlv(tbs).derEncoded
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
        shouldThrowAny { certificateDer.decodeFromByteArray<Certificate>(certificateDer.encodeToTlv(mismatched).derEncoded) }
    }

    "Existing PEM helpers use the certificate bridge and respect input limits" {
        val source = certificate()
        val pem = certificateDer.encodeToPem(source)
        DER.decodeFromPem<Certificate>(pem) shouldBe source
        shouldThrowAny { DER.decodeFromPem<Certificate>(pem, limit = 1) }
        shouldThrowAny { DER { serializersModule = signumX509Serializers; maxInputLength = 1 }.decodeFromPem<Certificate>(pem) }
    }
}
