package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.SubjectKeyIdentifierExtension

class KeyIdentifierValidator(
    private val certChain: CertificateChain,
    private var currentCertIndex: Int = 0
): CertificateValidator {
    @ExperimentalPkiApi
    override suspend fun check(
        currCert: X509Certificate,
        remainingCriticalExtensions: MutableSet<ObjectIdentifier>
    ) {
        currentCertIndex++
        checkSubjectKeyIdentifier(currCert)
    }

    fun checkTrustAnchorAndChild(trustAnchor: X509Certificate?, childCert: X509Certificate) {
        trustAnchor?.findExtension<AuthorityKeyIdentifierExtension>().let {
            if (trustAnchor?.isSelfIssued == false && it == null) throw CertificateChainValidatorException("Missing AuthorityKeyIdentifier extension in Trust Anchor.")
            if (it?.critical == true) throw CertificateChainValidatorException("Trust Anchor must mark AuthorityKeyIdentifier as non-critical")
        }

        trustAnchor?.let{ checkSubjectKeyIdentifier(it) }

        childCert.findExtension<AuthorityKeyIdentifierExtension>(). let{
            if (it == null) throw CertificateChainValidatorException("Missing AuthorityKeyIdentifier extension in certificate.")
            if (it.critical) throw CertificateChainValidatorException("Conforming CAs must mark AuthorityKeyIdentifier as non-critical")
        }
    }

    private fun checkSubjectKeyIdentifier(cert: X509Certificate) {
        cert.findExtension<SubjectKeyIdentifierExtension>().let {
            if (it == null) throw  CertificateChainValidatorException("Missing SubjectKeyIdentifier extension in certificate at index $currentCertIndex.")
            if (it.critical) throw CertificateChainValidatorException("SubjectKeyIdentifier extension must not be critical (index $currentCertIndex).")
        }
    }
}