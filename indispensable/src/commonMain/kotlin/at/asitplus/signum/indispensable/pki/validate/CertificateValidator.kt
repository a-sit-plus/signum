package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate

interface CertificateValidator {
    // Every validator removes checked critical extensions
    @ExperimentalPkiApi
    suspend fun check(currCert: X509Certificate, remainingCriticalExtensions: MutableSet<ObjectIdentifier>)
}