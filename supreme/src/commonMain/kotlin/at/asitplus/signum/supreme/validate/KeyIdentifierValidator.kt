package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CriticalAuthorityKeyIdentifierException
import at.asitplus.signum.CriticalSubjectKeyIdentifierException
import at.asitplus.signum.KeyIdentifierException
import at.asitplus.signum.MissingAuthorityKeyIdentifierException
import at.asitplus.signum.MissingSubjectKeyIdentifierException
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.SubjectKeyIdentifierExtension

class KeyIdentifierValidator: CertificateChainValidator {

    override suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext,
        checkedCriticalExtensions: MutableMap<X509Certificate, MutableSet<ObjectIdentifier>>
    ) {
        var currentCertIndex = 0
        for (currCert in chain) {
            currentCertIndex++
            checkSubjectKeyIdentifier(currCert, currentCertIndex)
        }
    }
}

@Throws(KeyIdentifierException::class)
fun checkTrustAnchorAndChild(trustAnchor: X509Certificate?, childCert: X509Certificate) {
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
private fun checkSubjectKeyIdentifier(cert: X509Certificate, currentCertIndex: Int? = null) {
    val location = currentCertIndex?.let { " at index $it" }.orEmpty()
    cert.findExtension<SubjectKeyIdentifierExtension>().let {
        if (it == null) throw  MissingSubjectKeyIdentifierException("Missing SubjectKeyIdentifier extension in certificate$location.")
        if (it.critical) throw CriticalSubjectKeyIdentifierException("SubjectKeyIdentifier extension must not be critical$location.")
    }
}