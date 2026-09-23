package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.CertificateChainValidatorException
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.checkValidityAt
import at.asitplus.signum.indispensable.pki.validationPath
import kotlin.time.Instant

/**
 * Checks the validity of the each certificate in the chain based on the given date and
 * confirms that each certificate was issued within the validity period of its issuer
 */
class TimeValidityValidator: CertificateChainValidator {

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        val date = context.date
        var currentCertIndex = 0
        val processingChain = anchoredChain.trustAnchor.cert?.let { anchoredChain.chain + it } ?: anchoredChain.chain

        for (currCert in processingChain.validationPath) {
            currCert.checkValidityAt(date)

            if (currentCertIndex < processingChain.validationPath.lastIndex) {
                val childCert = processingChain.validationPath[currentCertIndex + 1]
                currentCertIndex++
                wasCertificateIssuedWithinIssuerValidityPeriod(
                    dateOfIssuance = childCert.tbsCertificate.validFrom,
                    issuer = currCert,
                    processingChain.size - 1 - currentCertIndex)
            }
        }

        return emptyMap()
    }

    private fun wasCertificateIssuedWithinIssuerValidityPeriod(
        dateOfIssuance: Instant,
        issuer: X509Certificate,
        currentCertIndex: Int
    ) {
        val beginValidity = issuer.tbsCertificate.validFrom.epochSeconds
        val endValidity = issuer.tbsCertificate.validUntil.epochSeconds
        val issuanceCapped = dateOfIssuance.epochSeconds
        if (issuanceCapped !in beginValidity..endValidity) {
            throw CertificateChainValidatorException("Certificate at index $currentCertIndex issued outside issuer validity period.")
        }
    }
}