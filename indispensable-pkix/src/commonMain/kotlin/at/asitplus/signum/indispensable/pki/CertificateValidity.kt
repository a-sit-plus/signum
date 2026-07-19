package at.asitplus.signum.indispensable.pki

import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Throws if this certificate is not valid at [date] (i.e. expired or not yet valid).
 *
 * RFC 5280 only allows second granularities in the validity interval, with two conflicting
 * interpretations of how to handle the validity check:
 *
 * 1. Comparisons are performed at the granularity of the encoded representation, i.e. `floor(time)`.
 *    Under this interpretation, the chain is valid, since the entire millisecond interval
 *    `[0, .999...]` is truncated to `0`.
 * 2. Comparisons are instantaneous. Under this interpretation the chain is **invalid**, since 5
 *    milliseconds after the `notAfter` is factually after the `notAfter`.
 *
 * There is no clear "winning" interpretation here, although CAs in the Web PKI have filed and handled
 * compliance reports based on interpretation (1). **Hence, we truncate to seconds precision** (see
 * [Certificate.isExpired] / [Certificate.isNotYetValid]).
 */
@Throws(CertificateValidityException::class)
fun Certificate.checkValidityAt(date: Instant = Clock.System.now()) {
    if (isExpired(date)) throw CertificateExpiredException(tbsCertificate.validUntil, checkedAt = date)
    if (isNotYetValid(date)) throw CertificateNotYetValidException(tbsCertificate.validFrom, checkedAt = date)
}

/** Whether this certificate is valid at [date] (i.e. neither expired nor not-yet-valid). See [checkValidityAt]. */
fun Certificate.isValidAt(date: Instant = Clock.System.now()): Boolean =
    runCatching { checkValidityAt(date) }.isSuccess
