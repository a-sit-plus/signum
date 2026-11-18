package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.invoke
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.asn1
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Instant

private fun certificate(signatureAlgorithm: SignatureAlgorithm = EcdsaAlgorithm.withSHA256) = Certificate(
    TbsCertificate(
        serialNumber = BigInteger.ONE,
        signatureAlgorithm = signatureAlgorithm,
        issuerName = Name.EMPTY,
        subjectName = Name.EMPTY,
        validFrom = Instant.fromEpochSeconds(1_700_000_000),
        validUntil = Instant.fromEpochSeconds(1_800_000_000),
        publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
    ),
    EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO),
)

val CertificateEncodingTest by matrixSuite {

    "Equivalent signature identifiers preserve both certificate and signed TBS sources" {
        val ecdsa = EcdsaAlgorithm.withSHA256.asn1.toRepresentation()
        val pkcs1 = RsaAlgorithm.withSHA256andPKCS1Padding.asn1.toRepresentation()
        val pss = X509AlgorithmIdentifier(RsaSsaPssParams())
        val explicitPss = X509AlgorithmIdentifier(RsaSsaPssParams(
            hashAlgorithm = X509AlgorithmIdentifier(RsaSsaPssParams.SHA1_OID, null),
        ))
        for ((first, second) in listOf(
            ecdsa to X509AlgorithmIdentifier(ecdsa.oid, Asn1Null),
            pkcs1 to X509AlgorithmIdentifier(pkcs1.oid, null),
            pss to explicitPss,
        )) {
            for ((inner, outer) in listOf(first to second, second to first)) {
                val innerAlgorithm = SignatureAlgorithm.fromAsn1(inner)
                val outerAlgorithm = SignatureAlgorithm.fromAsn1(outer)
                innerAlgorithm shouldBe outerAlgorithm
                outerAlgorithm shouldBe innerAlgorithm
                innerAlgorithm.hashCode() shouldBe outerAlgorithm.hashCode()
                val template = certificate(innerAlgorithm).asn1.toRepresentation()
                val original = X509Certificate(template.tbsCertificate, outer, template.signatureValue)
                val bytes = Signum.Der.encodeToByteArray(original)
                val fromModel = Certificate.fromAsn1(original)
                val fromDer = Certificate.fromAsn1(bytes)

                fromDer shouldBe Certificate.fromAsn1(template)
                fromDer.hashCode() shouldBe Certificate.fromAsn1(template).hashCode()
                fromModel shouldBe fromDer
                fromModel.asn1.toRepresentation() shouldBeSameInstanceAs original
                fromModel.tbsCertificate.asn1.toRepresentation() shouldBeSameInstanceAs original.tbsCertificate
                fromDer.asn1.toRepresentation() shouldBe original
                fromDer.tbsCertificate.signatureAlgorithm.asn1.toRepresentation() shouldBe inner
                fromDer.asn1.toDer() shouldBe bytes
                fromDer.tbsCertificate.asn1.toDer() shouldBe Signum.Der.encodeToByteArray(original.tbsCertificate)
            }
        }
    }

    "Semantic matching rejects different digests, PSS settings and opaque parameters" {
        val pkcs1 = RsaAlgorithm.withSHA256andPKCS1Padding.asn1.toRepresentation()
        val pss = X509AlgorithmIdentifier(RsaSsaPssParams())
        val unknown = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null)
        for ((inner, outer) in listOf(
            pkcs1 to RsaAlgorithm.withSHA384andPKCS1Padding.asn1.toRepresentation(),
            pkcs1 to pss,
            pkcs1 to X509AlgorithmIdentifier(pkcs1.oid, Asn1Sequence(emptyList())),
            pss to X509AlgorithmIdentifier(pss.oid, null),
            pss to X509AlgorithmIdentifier(pss.oid, Asn1Null),
            pss to X509AlgorithmIdentifier(RsaSsaPssParams(saltLength = 21)),
            pss to X509AlgorithmIdentifier(RsaSsaPssParams(
                maskGenAlgorithm = RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(Digest.SHA256)
                    .asn1.toRepresentation(),
            )),
            unknown to X509AlgorithmIdentifier(unknown.oid, Asn1Null),
        )) {
            val template = certificate(SignatureAlgorithm.fromAsn1(inner)).asn1.toRepresentation()
            val mismatched = X509Certificate(template.tbsCertificate, outer, template.signatureValue)
            shouldThrowAny { Certificate.fromAsn1(mismatched) }
            shouldThrowAny { Certificate.fromAsn1(Signum.Der.encodeToByteArray(mismatched)) }
        }
    }

    "Retained outer and signed TBS models do not require supported algorithms" {
        val template = certificate().asn1.toRepresentation()
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
        Certificate.fromAsn1(original).asn1.toRepresentation()  shouldBeSameInstanceAs original
        shouldThrow<UnsupportedCryptoException> { decoded.signature }
    }

    "Outer signature algorithm must match the signed TBS algorithm" {
        val source = certificate().asn1.toRepresentation()
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
