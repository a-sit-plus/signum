package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.CertificateException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlin.coroutines.cancellation.CancellationException

interface CertificateValidator {
    // Every validator removes checked critical extensions
    @ExperimentalPkiApi
    @Throws(CertificateException::class, CancellationException::class)
    suspend fun check(currCert: X509Certificate, remainingCriticalExtensions: MutableSet<ObjectIdentifier>)
}