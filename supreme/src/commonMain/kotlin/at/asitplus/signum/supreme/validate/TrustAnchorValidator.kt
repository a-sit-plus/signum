package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.validate.CertificateValidator
import org.kotlincrypto.error.CertificateException

/**
 * This validator checks whether any certificate in the chain is issued by a trusted anchor
 * from the provided [trustAnchors] set
 */
class TrustAnchorValidator(
    private val trustAnchors: Set<TrustAnchor>,
    private val certChain: CertificateChain,
    private var currentCertIndex: Int = 0
) : CertificateValidator {

    private var foundTrusted: Boolean = false

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
        }

        if (currentCertIndex == certChain.lastIndex && !foundTrusted) {
            throw CertificateException("No trusted issuer found in the chain.")
        }

        currentCertIndex++

    }
}