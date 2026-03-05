package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.ExtendedKeyUsageException
import at.asitplus.signum.KeyUsageException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.ExtendedKeyUsageExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsage
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsageExtension
import at.asitplus.signum.indispensable.pki.validationPath
import kotlin.math.exp

/**
 * Ensures that intermediate CA certificates have the necessary key usage extensions.
 * Checks Expected Key Usage in leaf certificate only
 * Key usage to sign certificates (keyCertSign) and CRLSign is required according to RFC 5280.
 */
class KeyUsageValidator: CertificateChainValidator {

    private val supportedExtensions: Set<ObjectIdentifier> = setOf(
        KnownOIDs.keyUsage,
        KnownOIDs.extKeyUsage
    )

    @ExperimentalPkiApi
    override suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        val certPathLen = chain.size
        var currentCertIndex = 0
        val checkedCriticalExtensions = mutableMapOf<X509Certificate, MutableSet<ObjectIdentifier>>()

        for (currCert in chain.validationPath) {
            checkedCriticalExtensions
                .getOrPut(currCert) { mutableSetOf() }
                .addAll(supportedExtensions)
            currentCertIndex++
            val originalIndex = certPathLen - 1 - currentCertIndex
            if (currentCertIndex <= certPathLen - 1) {
                verifySignatureKeyUsage(currCert, context.supportRevocationChecking, originalIndex)
            }
            else {
                verifyExpectedEKU(currCert, context.expectedEku)
                context.leafKeyUsageCheck(currCert)
            }
        }
        return checkedCriticalExtensions.mapValues { it.value.toSet() }
    }

    private fun verifySignatureKeyUsage(currCert: X509Certificate, supportRevocationChecking: Boolean, currentCertIndex: Int) {
        if (currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.KEY_CERT_SIGN) != true) {
            throw KeyUsageException("Digital signature key usage extension not present at cert index $currentCertIndex.")
        }
        if (supportRevocationChecking && currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.CRL_SIGN) != true) {
            throw KeyUsageException("CRL signature key usage extension not present at cert index $currentCertIndex.")
        }
    }

    private fun verifyExpectedEKU(currCert: X509Certificate, expectedEku: Set<ObjectIdentifier>) {
        val eku = currCert.findExtension<ExtendedKeyUsageExtension>()
        if (eku != null && eku.keyUsages.isEmpty()) throw ExtendedKeyUsageException("Empty EKU extension in leaf certificate.")
        for (identifier in expectedEku) {
            if (eku?.keyUsages?.contains(identifier) == false) throw ExtendedKeyUsageException("Missing EKU $identifier in leaf certificate.")
        }
    }
}