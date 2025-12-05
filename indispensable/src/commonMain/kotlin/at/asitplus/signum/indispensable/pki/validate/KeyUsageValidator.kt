package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.ExtendedKeyUsageException
import at.asitplus.signum.KeyUsageException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.ExtendedKeyUsageExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsage
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsageExtension

/**
 * Ensures that intermediate CA certificates have the necessary key usage extensions.
 * Key usage to sign certificates (keyCertSign) and sign certificate revocation lists (cRLSign), according to RFC 5280.
 */
class KeyUsageValidator (
    private val pathLength: Int,
    private var currentCertIndex: Int = 0,
    private val expectedEku: Set<ObjectIdentifier> = emptySet()
) : CertificateValidator {

    private var supportedExtensions: Set<ObjectIdentifier> = setOf(
        KnownOIDs.keyUsage,
        KnownOIDs.extKeyUsage,
        KnownOIDs.subjectAltName_2_5_29_17,
    )

    @ExperimentalPkiApi
    override suspend fun check(currCert: X509Certificate, remainingCriticalExtensions: MutableSet<ObjectIdentifier>) {
        remainingCriticalExtensions.removeAll(supportedExtensions)
        currentCertIndex++
        if (currentCertIndex <= pathLength - 1)
            verifyIntermediateKeyUsage(currCert)
        else {
            verifyExpectedEKU(currCert)
            val basicConstraints = currCert.findExtension<BasicConstraintsExtension>()
            
            if (basicConstraints?.ca == true && currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.KEY_CERT_SIGN) != true) {
                throw KeyUsageException("Digital signature key usage extension not present at cert index $currentCertIndex.")
            }

            if (basicConstraints?.ca != true && currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.KEY_CERT_SIGN) == true) {
                throw KeyUsageException("Digital signature key usage extension must not be present at leaf cert.")
            }
        }
    }

    private fun verifyIntermediateKeyUsage(currCert: X509Certificate) {
        if (currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.KEY_CERT_SIGN) != true) {
            throw KeyUsageException("Digital signature key usage extension not present at cert index $currentCertIndex.")
        }

        if (currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.CRL_SIGN) != true) {
            throw KeyUsageException("CRL signature key usage extension not present at cert index $currentCertIndex.")
        }
    }

    private fun verifyExpectedEKU(currCert: X509Certificate) {
        val eku = currCert.findExtension<ExtendedKeyUsageExtension>()
        if (eku != null && eku.keyUsages.isEmpty()) throw ExtendedKeyUsageException("Empty EKU extension in leaf certificate.")
        for (identifier in expectedEku) {
            if (eku?.keyUsages?.contains(identifier) == false) throw ExtendedKeyUsageException("Missing EKU $identifier in leaf certificate.")
        }
    }
}