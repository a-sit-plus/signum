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
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Instant
import kotlin.uuid.Uuid

val UnknownOidTest by matrixSuite {
    val unknownAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier(Uuid.random()), Asn1Null)
    val publicKeyInfo = SubjectPublicKeyInfo(unknownAlgorithm, Asn1BitString(byteArrayOf(1, 2, 3)))
    val signatureValue = X509SignatureValue(byteArrayOf(4, 5, 6))

    "unknown signature, digest and MAC algorithms retain their DER until used" {
        val encoded = DER.encodeToByteArray(unknownAlgorithm)
        val signature = SignatureAlgorithm.decodeFromDer(encoded)
        val digest = Digest.decodeFromDer(encoded)
        val mac = MessageAuthenticationCode.decodeFromDer(encoded)

        signature.encodeToDer() shouldBe encoded
        digest.encodeToDer() shouldBe encoded
        mac.encodeToDer() shouldBe encoded
        signature shouldBe SignatureAlgorithm.decodeFromDer(encoded)
        digest shouldBe Digest.decodeFromDer(encoded)
        mac shouldBe MessageAuthenticationCode.decodeFromDer(encoded)
        signature.hashCode() shouldBe SignatureAlgorithm.decodeFromDer(encoded).hashCode()
        digest.hashCode() shouldBe Digest.decodeFromDer(encoded).hashCode()
        mac.hashCode() shouldBe MessageAuthenticationCode.decodeFromDer(encoded).hashCode()
        signature shouldNotBe SignatureAlgorithm.decodeFromTlv(
            X509AlgorithmIdentifier(ObjectIdentifier(Uuid.random()), Asn1Null)
        )
        shouldThrow<UnsupportedCryptoException> { signature.preHashedSignatureFormat }
        shouldThrow<UnsupportedCryptoException> { digest.outputLength }
        shouldThrow<UnsupportedCryptoException> { mac.outputLength }
    }

    "unknown public and private key algorithms round-trip without interpreting key bytes" {
        val publicDer = DER.encodeToByteArray(publicKeyInfo)
        val publicKey = CryptoPublicKey.decodeFromDer(publicDer)
        publicKey.encodeToDer() shouldBe publicDer
        publicKey shouldBe CryptoPublicKey.decodeFromDer(publicDer)
        publicKey.hashCode() shouldBe CryptoPublicKey.decodeFromDer(publicDer).hashCode()
        shouldThrow<UnsupportedCryptoException> { publicKey.didEncoded }

        val privateKeyInfo = Pkcs8PrivateKeyInfo(unknownAlgorithm, Asn1OctetString(byteArrayOf(7, 8, 9)))
        val privateDer = DER.encodeToByteArray(privateKeyInfo)
        val privateKey = CryptoPrivateKey.decodeFromDer(privateDer)
        privateKey.encodeToDer() shouldBe privateDer
        privateKey shouldBe CryptoPrivateKey.decodeFromDer(privateDer)
        privateKey.hashCode() shouldBe CryptoPrivateKey.decodeFromDer(privateDer).hashCode()
    }

    "certificate with unknown signature and key OIDs can be decoded and re-encoded" {
        val tbs = X509TbsCertificate(
            serialNumber = Asn1Integer.ONE,
            signatureAlgorithm = unknownAlgorithm,
            issuerName = X500Name.EMPTY.asn1Representation,
            validFrom = Asn1Time.SecondsCapped(Instant.parse("2026-01-01T00:00:00Z")),
            validUntil = Asn1Time.SecondsCapped(Instant.parse("2027-01-01T00:00:00Z")),
            subjectName = X500Name.EMPTY.asn1Representation,
            subjectPublicKeyInfo = publicKeyInfo,
        )
        val encoded = DER.encodeToByteArray(X509Certificate(tbs, unknownAlgorithm, signatureValue))
        val certificate = Certificate.decodeFromDer(encoded)

        certificate.encodeToDer() shouldBe encoded
        certificate.tbsCertificate.serialNumber shouldBe Asn1Integer.ONE
        certificate.tbsCertificate.signatureAlgorithm.asn1Representation shouldBe unknownAlgorithm
        certificate.publicKey.asn1Representation shouldBe publicKeyInfo
        certificate.signatureValue.asn1Representation shouldBe signatureValue
        certificate shouldBe Certificate.decodeFromDer(encoded)
        certificate.hashCode() shouldBe Certificate.decodeFromDer(encoded).hashCode()
        shouldThrow<UnsupportedCryptoException> { certificate.signature }
    }

    "CSR with an unknown public key OID retains its subject, key and signature" {
        val subject = X500Name.fromString("CN=Unknown key")
        val algorithm = RsaAlgorithm.withSHA256andPKCS1Padding
        val request = Pkcs10CertificationRequest(
            Pkcs10CertificationRequestInfo(subjectName = subject.asn1Representation, publicKey = publicKeyInfo),
            algorithm.asn1Representation,
            signatureValue,
        )
        val encoded = DER.encodeToByteArray(request)
        val decoded = CertificationRequest.decodeFromDer(encoded)

        decoded.encodeToDer() shouldBe encoded
        decoded.tbsCsr.subjectName shouldBe subject
        decoded.tbsCsr.publicKey.asn1Representation shouldBe publicKeyInfo
        decoded.signatureAlgorithm shouldBe algorithm
        decoded.signature.asn1Representation shouldBe signatureValue
        decoded shouldBe CertificationRequest.decodeFromDer(encoded)
        decoded.hashCode() shouldBe CertificationRequest.decodeFromDer(encoded).hashCode()
        shouldThrow<UnsupportedCryptoException> { decoded.tbsCsr.publicKey.didEncoded }
    }
}
