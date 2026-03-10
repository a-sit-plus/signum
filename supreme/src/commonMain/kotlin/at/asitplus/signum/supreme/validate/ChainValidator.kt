package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.root
import at.asitplus.signum.indispensable.pki.validationPath
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify

/**
 * Validator that ensures the integrity and correctness of a certificate chain.
 *
 * This validator verifies that each certificate is properly signed by its issuer,
 * ensures that the subject of the issuer certificate matches the issuer of the child certificate.
 */
class ChainValidator: CertificateChainValidator {

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        var currentCertIndex = 0
        val trustAnchor = anchoredChain.trustAnchor
        val processingChain = trustAnchor.cert?.let { anchoredChain.chain + it } ?: anchoredChain.chain
        for (currCert in processingChain.validationPath) {
            if (currentCertIndex < processingChain.validationPath.lastIndex) {
                val childCert = processingChain.validationPath[currentCertIndex + 1]
                verifySignature(childCert, issuer = currCert, childCert == processingChain.validationPath.last())
                subjectAndIssuerPrincipalMatch(childCert, issuer = currCert)
                currentCertIndex++
            }
        }

        // only if trust anchor is key based
        if (trustAnchor.cert == null) {
            if (!trustAnchor.isIssuerOf(processingChain.root)) {
                throw CertificateChainValidatorException(
                    "Root certificate not issued by trust anchor."
                )
            }
        }
        return emptyMap()
    }

    private suspend fun verifySignature(
        cert: X509Certificate,
        issuer: X509Certificate,
        isLeaf: Boolean,
    ) {
        val verifier = (cert.signatureAlgorithm as X509SignatureAlgorithm).verifierFor(issuer.decodedPublicKey.getOrThrow()).getOrThrow()
        if (!verifier.verify(cert.tbsCertificate.encodeToDer(), cert.decodedSignature.getOrThrow()).isSuccess) {
            throw CryptoOperationFailed("Signature verification failed in ${if (isLeaf) "leaf" else "CA"} certificate.")
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
}