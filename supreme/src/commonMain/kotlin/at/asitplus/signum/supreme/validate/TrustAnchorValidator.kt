package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.NoTrustedIssuerFoundException
import at.asitplus.signum.TrustAnchorKeyMismatchException
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlin.text.compareTo
import kotlin.text.get
import kotlin.time.Instant

/**
 * This validator checks whether any certificate in the chain is issued by a trusted anchor
 * from the provided [trustAnchors] set
 */
class TrustAnchorValidator: CertificateChainValidator {

    var foundTrusted: Boolean = false
    var trustAnchor: TrustAnchor? = null

    @ExperimentalPkiApi
    override suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        val trustAnchors = context.trustAnchors
        var currentCertIndex= 0
        val date = context.date
        foundTrusted = false
        trustAnchor = null

        for (currCert in chain) {
            if (foundTrusted) continue
            val issuingAnchor = trustAnchors.firstOrNull { anchor ->
                anchor.isIssuerOf(currCert)
            }

            if (issuingAnchor != null) {
                foundTrusted = true

                if (currentCertIndex < chain.lastIndex) {
                    val nextCert = chain[currentCertIndex + 1]

                    val anchorKey = issuingAnchor.publicKey
                    val nextIssuerKey = nextCert.decodedPublicKey.getOrThrow()

                    if (anchorKey != nextIssuerKey) {
                        throw TrustAnchorKeyMismatchException("Public key of certificate at index ${currentCertIndex + 1} does not match the issuing trust anchor.")

                    }
                }

                trustAnchor = issuingAnchor

                issuingAnchor.cert?.let { checkCaBasicConstraints(it) }

                issuingAnchor.cert?.checkValidityAt(date)

                issuingAnchor.cert?.let { checkTrustAnchorAndChild(it, currCert) }
            }

            if (currentCertIndex == chain.lastIndex && !foundTrusted) {
                throw NoTrustedIssuerFoundException("No trusted issuer found in the trust anchor chain.")
            }

            currentCertIndex++
        }

        return emptyMap()
    }
}