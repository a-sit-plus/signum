package at.asitplus.signum.supreme.validate
import at.asitplus.signum.indispensable.pki.findExtension

import at.asitplus.signum.indispensable.pki.CriticalAuthorityKeyIdentifierException
import at.asitplus.signum.indispensable.pki.CriticalSubjectKeyIdentifierException
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.KeyIdentifierException
import at.asitplus.signum.indispensable.pki.MissingAuthorityKeyIdentifierException
import at.asitplus.signum.indispensable.pki.MissingSubjectKeyIdentifierException
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.extn.AuthorityKeyIdentifier
import at.asitplus.signum.indispensable.pki.extn.SubjectKeyIdentifier
import at.asitplus.signum.indispensable.pki.root

class KeyIdentifierValidator: CertificateValidator {

    @ExperimentalPkiApi
    override suspend fun check(currCert: X509Certificate): Set<ObjectIdentifier> {
        checkSubjectKeyIdentifier(currCert)
        return emptySet()
    }

    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        anchoredChain.trustAnchor.cert?.let { checkTrustAnchorAndChild(it, anchoredChain.chain.root) }
        return super.validate(anchoredChain, context)
    }

    @Throws(KeyIdentifierException::class)
    private fun checkTrustAnchorAndChild(trustAnchor: X509Certificate?, childCert: X509Certificate) {
        trustAnchor?.findExtension<AuthorityKeyIdentifier>().let {
            if (trustAnchor?.isSelfIssued == false && it == null) throw MissingAuthorityKeyIdentifierException("Missing AuthorityKeyIdentifier extension in Trust Anchor.")
            if (it?.critical == true) throw CriticalAuthorityKeyIdentifierException("Trust Anchor must mark AuthorityKeyIdentifier as non-critical")
        }

        trustAnchor?.let{ checkSubjectKeyIdentifier(it) }

        childCert.findExtension<AuthorityKeyIdentifier>(). let{
            if (it == null) throw MissingAuthorityKeyIdentifierException("Missing AuthorityKeyIdentifier extension in certificate.")
            if (it.critical) throw CriticalAuthorityKeyIdentifierException("Conforming CAs must mark AuthorityKeyIdentifier as non-critical")
        }
    }

    @Throws(KeyIdentifierException::class)
    private fun checkSubjectKeyIdentifier(cert: X509Certificate) {
        cert.findExtension<SubjectKeyIdentifier>().let {
            if (it == null) throw  MissingSubjectKeyIdentifierException("Missing SubjectKeyIdentifier extension in certificate.")
            if (it.critical) throw CriticalSubjectKeyIdentifierException("SubjectKeyIdentifier extension must not be critical.")
        }
    }
}