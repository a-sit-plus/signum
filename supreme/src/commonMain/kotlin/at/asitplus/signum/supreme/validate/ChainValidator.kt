package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CertificateValidityException
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.SubjectKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.validate.CertificateValidator
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify

/**
 * Validator that ensures the integrity and correctness of a certificate chain.
 *
 * This validator verifies that each certificate is properly signed by its issuer,
 * ensures that the subject of the issuer certificate matches the issuer of the child certificate.
 */
class ChainValidator(
    private val certificateChain: CertificateChain,
    private var currentCertIndex: Int = 0
) : CertificateValidator {

    @ExperimentalPkiApi
    override suspend fun check(
        currCert: X509Certificate,
        remainingCriticalExtensions: MutableSet<ObjectIdentifier>
    ) {
        if (currentCertIndex < certificateChain.lastIndex) {
            val childCert = certificateChain[currentCertIndex + 1]
            verifySignature(childCert, issuer = currCert, childCert == certificateChain.last())
            subjectAndIssuerPrincipalMatch(childCert, issuer = currCert)
            currentCertIndex++
        }
        isSanCriticalWhenNameIsEmpty(currCert)
        isSKIcritical(currCert)
    }

    private fun verifySignature(
        cert: X509Certificate,
        issuer: X509Certificate,
        isLeaf: Boolean,
    ) {
        val verifier = (cert.signatureAlgorithm as X509SignatureAlgorithm).verifierFor(issuer.decodedPublicKey.getOrThrow()).getOrThrow()
        if (!verifier.verify(cert.tbsCertificate.encodeToDer(), cert.decodedSignature.getOrThrow()).isSuccess) {
            throw CryptoOperationFailed("Signature verification failed in ${if (isLeaf) "leaf" else "CA"} certificate.")
        }

        if (!cert.isSelfIssued) {
            if (cert.findExtension<AuthorityKeyIdentifierExtension>() == null) throw CertificateChainValidatorException("Missing AuthorityKeyIdentifier extension in certificate.")
        }
    }

    private fun subjectAndIssuerPrincipalMatch(
        cert: X509Certificate,
        issuer: X509Certificate
    ) {
        val issuerInChildPrincipal = cert.tbsCertificate.issuerName
        val subjectInIssuerPrincipal = issuer.tbsCertificate.subjectName
        if (issuerInChildPrincipal != subjectInIssuerPrincipal) {
            throw CertificateChainValidatorException("Subject of issuer cert and issuer of child certificate mismatch.")
        }

        if (cert.tbsCertificate.issuerUniqueID != issuer.tbsCertificate.subjectUniqueID) {
            throw CertificateChainValidatorException("UID of issuer cert and UID of issuer in child certificate mismatch.")
        }
    }

    private fun isSanCriticalWhenNameIsEmpty(cert: X509Certificate) {
        val sanExtension = cert.tbsCertificate.extensions?.find { it.oid == KnownOIDs.subjectAltName_2_5_29_17 }
        if (cert.tbsCertificate.subjectName.relativeDistinguishedNames.isEmpty() && sanExtension?.critical == false)
            throw CertificateChainValidatorException("SAN extension is not critical, which is required when subject is empty.")

    }

    private fun isSKIcritical(cert: X509Certificate) {
        cert.findExtension<SubjectKeyIdentifierExtension>().let {
            if (it == null) throw  CertificateChainValidatorException("Missing SubjectKeyIdentifier extension in certificate.")
            if (it.critical) throw CertificateChainValidatorException("SKI extension must not be critical.")
        }
    }
}