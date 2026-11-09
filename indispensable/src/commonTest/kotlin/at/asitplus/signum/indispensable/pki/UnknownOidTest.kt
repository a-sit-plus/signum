package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.fromAsn1
import at.asitplus.signum.indispensable.sign.toAsn1
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.time.Instant
import kotlin.uuid.Uuid
import kotlinx.serialization.encodeToByteArray

val UnknownOidTest by matrixSuite {
    val unknownAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier(Uuid.random()), Asn1Null)
    val publicKeyInfo = SubjectPublicKeyInfo(unknownAlgorithm, Asn1BitString(byteArrayOf(1, 2, 3)))
    val signatureValue = X509SignatureValue(byteArrayOf(4, 5, 6))

    "unknown signature, digest and MAC algorithms retain their DER until used" {
        val encoded = DER.encodeToByteArray(unknownAlgorithm)
        val signature = SignatureAlgorithm.fromAsn1(encoded)
        val digest = Digest.fromAsn1(encoded)
        val mac = MessageAuthenticationCode.fromAsn1(encoded)

        signature.toAsn1.DER() shouldBe encoded
        digest.toAsn1.DER() shouldBe encoded
        mac.toAsn1.DER() shouldBe encoded
        signature shouldBe SignatureAlgorithm.fromAsn1(encoded)
        digest shouldBe Digest.fromAsn1(encoded)
        mac shouldBe MessageAuthenticationCode.fromAsn1(encoded)
        signature.hashCode() shouldBe SignatureAlgorithm.fromAsn1(encoded).hashCode()
        digest.hashCode() shouldBe Digest.fromAsn1(encoded).hashCode()
        mac.hashCode() shouldBe MessageAuthenticationCode.fromAsn1(encoded).hashCode()
        signature shouldNotBe SignatureAlgorithm.fromAsn1(
            X509AlgorithmIdentifier(ObjectIdentifier(Uuid.random()), Asn1Null)
        )
        shouldThrow<UnsupportedCryptoException> { signature.preHashedSignatureFormat }
        shouldThrow<UnsupportedCryptoException> { digest.outputLength }
        shouldThrow<UnsupportedCryptoException> { mac.outputLength }
    }

    "unknown public and private key algorithms round-trip without interpreting key bytes" {
        val publicDer = DER.encodeToByteArray(publicKeyInfo)
        val publicKey = CryptoPublicKey.fromAsn1(publicDer)
        publicKey.toAsn1.DER() shouldBe publicDer
        publicKey shouldBe CryptoPublicKey.fromAsn1(publicDer)
        publicKey.hashCode() shouldBe CryptoPublicKey.fromAsn1(publicDer).hashCode()
        shouldThrow<UnsupportedCryptoException> { publicKey.didEncoded }

        val privateKeyInfo = Pkcs8PrivateKeyInfo(unknownAlgorithm, Asn1OctetString(byteArrayOf(7, 8, 9)))
        val privateDer = DER.encodeToByteArray(privateKeyInfo)
        val privateKey = CryptoPrivateKey.fromAsn1(privateDer)
        privateKey.toAsn1.DER() shouldBe privateDer
        privateKey shouldBe CryptoPrivateKey.fromAsn1(privateDer)
        privateKey.hashCode() shouldBe CryptoPrivateKey.fromAsn1(privateDer).hashCode()
    }

    "certificate with unknown signature and key OIDs can be decoded and re-encoded" {
        val tbs = X509TbsCertificate(
            serialNumber = Asn1Integer.ONE,
            signatureAlgorithm = unknownAlgorithm,
            issuerName = Name.EMPTY.toAsn1(),
            validFrom = Asn1Time.SecondsCapped(Instant.parse("2026-01-01T00:00:00Z")),
            validUntil = Asn1Time.SecondsCapped(Instant.parse("2027-01-01T00:00:00Z")),
            subjectName = Name.EMPTY.toAsn1(),
            subjectPublicKeyInfo = publicKeyInfo,
        )
        val encoded = DER.encodeToByteArray(X509Certificate(tbs, unknownAlgorithm, signatureValue))
        val certificate = Certificate.fromAsn1(encoded)

        certificate.toAsn1.DER() shouldBe encoded
        certificate.tbsCertificate.serialNumber shouldBe BigInteger.ONE
        certificate.tbsCertificate.signatureAlgorithm.toAsn1() shouldBe unknownAlgorithm
        certificate.publicKey.toAsn1() shouldBe publicKeyInfo
        certificate.signatureValue.toAsn1() shouldBe signatureValue
        certificate shouldBe Certificate.fromAsn1(encoded)
        certificate.hashCode() shouldBe Certificate.fromAsn1(encoded).hashCode()
        shouldThrow<UnsupportedCryptoException> { certificate.signature }
    }

    "CSR with an unknown public key OID retains its subject, key and signature" {
        val subject = Name.fromString("CN=Unknown key")
        val algorithm = RsaAlgorithm.withSHA256andPKCS1Padding
        val request = Pkcs10CertificationRequest(
            Pkcs10CertificationRequestInfo(subjectName = subject.toAsn1(), publicKey = publicKeyInfo),
            algorithm.toAsn1(),
            signatureValue,
        )
        val encoded = DER.encodeToByteArray(request)
        val decoded = CertificationRequest.fromAsn1(encoded)

        decoded.toAsn1.DER() shouldBe encoded
        decoded.tbsCsr.subjectName shouldBe subject
        decoded.tbsCsr.publicKey.toAsn1() shouldBe publicKeyInfo
        decoded.signatureAlgorithm shouldBe algorithm
        decoded.signature.toAsn1() shouldBe signatureValue
        decoded shouldBe CertificationRequest.fromAsn1(encoded)
        decoded.hashCode() shouldBe CertificationRequest.fromAsn1(encoded).hashCode()
        shouldThrow<UnsupportedCryptoException> { decoded.tbsCsr.publicKey.didEncoded }
    }
}
