package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.CertificateValidityException
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Instant

/**
 * Checks the validity of the each certificate in the chain based on the given date.
 */
class TimeValidityValidator(
    val date: Instant
) : CertificateValidator {

    override suspend fun check(
        currCert: X509Certificate,
        remainingCriticalExtensions: MutableSet<ObjectIdentifier>
    ) {
        if (currCert.isExpired(date)) {
            throw CertificateValidityException(
                "certificate expired on " + currCert.tbsCertificate.validUntil.instant.toLocalDateTime(
                    TimeZone.currentSystemDefault()
                )
            )
        }

        if (currCert.isNotYetValid(date)) {
            throw CertificateValidityException(
                "certificate not valid till " + currCert.tbsCertificate.validFrom.instant.toLocalDateTime(
                    TimeZone.currentSystemDefault()
                )
            )
        }
    }
}