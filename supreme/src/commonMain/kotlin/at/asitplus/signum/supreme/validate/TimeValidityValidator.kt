package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlin.time.Instant

/**
 * Checks the validity of the each certificate in the chain based on the given date and
 * confirms that each certificate was issued within the validity period of its issuer
 */
class TimeValidityValidator: CertificateChainValidator {

    @ExperimentalPkiApi
    override suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        val date = context.date
        var currentCertIndex = 0

        for (currCert in chain) {
            currCert.checkValidityAt(date)

            if (currentCertIndex < chain.lastIndex) {
                val childCert = chain[currentCertIndex + 1]
                currentCertIndex++
                wasCertificateIssuedWithinIssuerValidityPeriod(
                    dateOfIssuance = childCert.tbsCertificate.validFrom.instant,
                    issuer = currCert,
                    currentCertIndex)
            }
        }

        return emptyMap()
    }

    private fun wasCertificateIssuedWithinIssuerValidityPeriod(
        dateOfIssuance: Instant,
        issuer: X509Certificate,
        currentCertIndex: Int
    ) {
        val beginValidity = issuer.tbsCertificate.validFrom.instant
        val endValidity = issuer.tbsCertificate.validUntil.instant
        if (beginValidity > dateOfIssuance || dateOfIssuance > endValidity) {
            throw CertificateChainValidatorException("Certificate at index $currentCertIndex issued outside issuer validity period.")
        }
    }
}