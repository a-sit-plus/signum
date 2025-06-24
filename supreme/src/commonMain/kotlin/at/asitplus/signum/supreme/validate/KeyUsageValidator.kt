package at.asitplus.signum.supreme.validate

import at.asitplus.signum.KeyUsageException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsage
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsageExtension

class KeyUsageValidator (
    private val pathLength: Int,
    private var currentCertIndex: Int = 0,
) : CertificateValidator {

    override fun check(currCert: X509Certificate, remainingCriticalExtensions: MutableSet<ObjectIdentifier>) {
        if (currentCertIndex < pathLength - 1)
            verifyIntermediateKeyUsage(currCert)

        currentCertIndex++

        remainingCriticalExtensions.remove(KnownOIDs.keyUsage)
        remainingCriticalExtensions.remove(KnownOIDs.extKeyUsage)
        remainingCriticalExtensions.remove(KnownOIDs.subjectAltName_2_5_29_17)
    }

    private fun verifyIntermediateKeyUsage(currCert: X509Certificate) {
        if (currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.KEY_CERT_SIGN) != true) {
            throw KeyUsageException("Digital signature key usage extension not present at the intermediate cert!")
        }

        if (currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.CRL_SIGN) != true) {
            throw KeyUsageException("CRL signature key usage extension not present at the intermediate cert!")
        }
    }
}