package at.asitplus.signum.supreme.validate
import at.asitplus.signum.indispensable.encodeToDer

import at.asitplus.signum.indispensable.pki.CertificateChainValidatorException
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.X500Name
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
        val verifier = cert.signatureAlgorithm.verifierFor(issuer.publicKey).getOrThrow()
        if (!verifier.verify(cert.tbsCertificate.encodeToDer(), cert.signature).isSuccess) {
            throw CryptoOperationFailed("Signature verification failed in ${if (isLeaf) "leaf" else "CA"} certificate.")
        }
    }

    private fun subjectAndIssuerPrincipalMatch(
        cert: X509Certificate,
        issuer: X509Certificate
    ) {
        val issuerInChildPrincipal = cert.tbsCertificate.issuerName
        val subjectInIssuerPrincipal = issuer.tbsCertificate.subjectName
        // RFC 5280 §7.1 name matching: compare canonicalized DNs (case-insensitive, whitespace-collapsed;
        // PrintableString/UTF8String compare equal since both decode to the same text). Byte-exact `==`
        // on the awesn1-backed Name would reject valid equivalent name chains.
        if (issuerInChildPrincipal.canonicalForMatching() != subjectInIssuerPrincipal.canonicalForMatching()) {
            throw CertificateChainValidatorException("Subject of issuer cert and issuer of child certificate mismatch.")
        }

        if (!cert.tbsCertificate.issuerUniqueID.contentEquals(issuer.tbsCertificate.subjectUniqueID)) {
            throw CertificateChainValidatorException("UID of issuer cert and UID of issuer in child certificate mismatch.")
        }
    }

    /** RFC 5280 §7.1 canonical form of a [Name] for issuer/subject matching. */
    private fun Name.canonicalForMatching(): String =
        (this as? X500Name)?.toRfc2253String()?.lowercase()?.replace(Regex("\\s+"), " ")?.trim()
            ?: toString()
}