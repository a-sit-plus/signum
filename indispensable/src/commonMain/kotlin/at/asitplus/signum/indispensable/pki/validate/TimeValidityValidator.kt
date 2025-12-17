package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CertificateValidityException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Instant

/**
 * Checks the validity of the each certificate in the chain based on the given date and
 * confirms that each certificate was issued within the validity period of its issuer
 */
class TimeValidityValidator(
    val date: Instant,
    private val certChain: CertificateChain,
    private var currentCertIndex: Int = 0,
    private val checkLeafValidity: Boolean = true
) : CertificateValidator {

    @ExperimentalPkiApi
    override suspend fun check(
        currCert: X509Certificate,
        remainingCriticalExtensions: MutableSet<ObjectIdentifier>
    ) {
        // check leaf validity only if checkLeafValidity is true, enforce validity for all other certificates
        if (currentCertIndex != certChain.lastIndex || (currentCertIndex == certChain.lastIndex && checkLeafValidity)) {
            if (currCert.isExpired(date)) {
                throw CertificateValidityException(
                    "certificate expired on " + currCert.tbsCertificate.validUntil.instant.toLocalDateTime(
                        TimeZone.UTC
                    )
                )
            }

            if (currCert.isNotYetValid(date)) {
                throw CertificateValidityException(
                    "certificate not valid till " + currCert.tbsCertificate.validFrom.instant.toLocalDateTime(
                        TimeZone.UTC
                    )
                )
            }
        }
        // perform this check on last two certificates only if checkLeafValidity is true
        if (currentCertIndex < certChain.lastIndex - 1 || (currentCertIndex == certChain.lastIndex - 1 && checkLeafValidity)) {
            val childCert = certChain[currentCertIndex + 1]
            wasCertificateIssuedWithinIssuerValidityPeriod(
                dateOfIssuance = childCert.tbsCertificate.validFrom.instant,
                issuer = currCert
            )
        }
        currentCertIndex++
    }

    private fun wasCertificateIssuedWithinIssuerValidityPeriod(
        dateOfIssuance: Instant,
        issuer: X509Certificate
    ) {
        val beginValidity = issuer.tbsCertificate.validFrom.instant
        val endValidity = issuer.tbsCertificate.validUntil.instant
        if (beginValidity > dateOfIssuance || dateOfIssuance > endValidity) {
            throw CertificateChainValidatorException("Certificate issued outside issuer validity period.")
        }
    }
}