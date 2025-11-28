package at.asitplus.signum.supreme.validate

import at.asitplus.signum.BasicConstraintsException
import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension
import at.asitplus.signum.indispensable.pki.validate.BasicConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.CertificateValidator
import org.kotlincrypto.error.CertificateException

/**
 * This validator checks whether any certificate in the chain is issued by a trusted anchor
 * from the provided [trustAnchors] set
 */
class TrustAnchorValidator(
    private val trustAnchors: Set<TrustAnchor>,
    private val certChain: CertificateChain,
    private var currentCertIndex: Int = 0,
    var trustAnchor: X509Certificate? = null
) : CertificateValidator {

    private var foundTrusted: Boolean = false
    private val basicConstraintsValidator: BasicConstraintsValidator = BasicConstraintsValidator(0)

    @ExperimentalPkiApi
    override suspend fun check(
        currCert: X509Certificate,
        remainingCriticalExtensions: MutableSet<ObjectIdentifier>
    ) {
        if (foundTrusted) return
        val issuingAnchor = trustAnchors.firstOrNull { anchor ->
            anchor.isIssuerOf(currCert)
        }

        if (issuingAnchor != null) {
            foundTrusted = true

            if (currentCertIndex < certChain.lastIndex) {
                val nextCert = certChain[currentCertIndex + 1]

                val anchorKey = issuingAnchor.publicKey
                val nextIssuerKey = nextCert.decodedPublicKey.getOrThrow()

                if (anchorKey != nextIssuerKey) {
                    throw CertificateException("Untrusted certificate: trust anchor key mismatch.")

                }
            }

            trustAnchor = issuingAnchor.cert

            issuingAnchor.cert?.let { basicConstraintsValidator.checkCaBasicConstraints(it) }


            issuingAnchor.cert?.findExtension<AuthorityKeyIdentifierExtension>().let {
                if (issuingAnchor.cert?.isSelfIssued == false && it == null) throw CertificateChainValidatorException("Missing AuthorityKeyIdentifier extension in Trust Anchor.")
                if (it?.critical == true) throw CertificateChainValidatorException("Trust Anchor must mark AuthorityKeyIdentifier as non-critical")
            }

            currCert.findExtension<AuthorityKeyIdentifierExtension>(). let{
                if (it == null) throw CertificateChainValidatorException("Missing AuthorityKeyIdentifier extension in certificate.")
                if (it.critical) throw CertificateChainValidatorException("Conforming CAs must mark AuthorityKeyIdentifier as non-critical")
            }
        }

        if (currentCertIndex == certChain.lastIndex && !foundTrusted) {
            throw CertificateException("No trusted issuer found in the chain.")
        }

        currentCertIndex++

    }
}