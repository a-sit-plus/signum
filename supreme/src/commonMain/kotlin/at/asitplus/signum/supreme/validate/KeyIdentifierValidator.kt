package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CriticalAuthorityKeyIdentifierException
import at.asitplus.signum.CriticalSubjectKeyIdentifierException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.KeyIdentifierException
import at.asitplus.signum.MissingAuthorityKeyIdentifierException
import at.asitplus.signum.MissingSubjectKeyIdentifierException
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.SubjectKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.root

class KeyIdentifierValidator: CertificateValidator {

    @ExperimentalPkiApi
    override suspend fun check(currCert: X509Certificate): Set<ObjectIdentifier> {
        checkSubjectKeyIdentifier(currCert)
        return emptySet()
    }

    override suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        context.selectedTrustAnchor?.cert?.let { checkTrustAnchorAndChild(it, chain.root) }
        return super.validate(chain, context)
    }

    @Throws(KeyIdentifierException::class)
    private fun checkTrustAnchorAndChild(trustAnchor: X509Certificate?, childCert: X509Certificate) {
        trustAnchor?.findExtension<AuthorityKeyIdentifierExtension>().let {
            if (trustAnchor?.isSelfIssued == false && it == null) throw MissingAuthorityKeyIdentifierException("Missing AuthorityKeyIdentifier extension in Trust Anchor.")
            if (it?.critical == true) throw CriticalAuthorityKeyIdentifierException("Trust Anchor must mark AuthorityKeyIdentifier as non-critical")
        }

        trustAnchor?.let{ checkSubjectKeyIdentifier(it) }

        childCert.findExtension<AuthorityKeyIdentifierExtension>(). let{
            if (it == null) throw MissingAuthorityKeyIdentifierException("Missing AuthorityKeyIdentifier extension in certificate.")
            if (it.critical) throw CriticalAuthorityKeyIdentifierException("Conforming CAs must mark AuthorityKeyIdentifier as non-critical")
        }
    }

    @Throws(KeyIdentifierException::class)
    private fun checkSubjectKeyIdentifier(cert: X509Certificate) {
        cert.findExtension<SubjectKeyIdentifierExtension>().let {
            if (it == null) throw  MissingSubjectKeyIdentifierException("Missing SubjectKeyIdentifier extension in certificate.")
            if (it.critical) throw CriticalSubjectKeyIdentifierException("SubjectKeyIdentifier extension must not be critical.")
        }
    }
}