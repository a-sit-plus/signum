package at.asitplus.signum.supreme.validate
import at.asitplus.signum.indispensable.pki.findExtension

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.ExtendedKeyUsageException
import at.asitplus.signum.indispensable.pki.KeyUsageException
import at.asitplus.awesn1.*
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.extn.ExtendedKeyUsage
import at.asitplus.signum.indispensable.pki.extn.UsageBit
import at.asitplus.signum.indispensable.pki.extn.KeyUsage
import at.asitplus.signum.indispensable.pki.validationPath

/**
 * Ensures that intermediate CA certificates have the necessary key usage extensions.
 * Checks Expected Key Usage in leaf certificate only
 * Key usage to sign certificates (keyCertSign) and CRLSign is required according to RFC 5280.
 *
 * Certificate-form trust anchors are subject to the same key usage checks as any path CA;
 * public-key anchors have no certificate to inspect and are therefore exempt.
 */
class KeyUsageValidator: CertificateChainValidator {

    private val supportedExtensions: Set<ObjectIdentifier> = setOf(
        KnownOIDs.keyUsage,
        KnownOIDs.extKeyUsage
    )

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        val certPathLen = anchoredChain.chain.size
        var currentCertIndex = 0
        val checkedCriticalExtensions = mutableMapOf<X509Certificate, MutableSet<ObjectIdentifier>>()

        for (currCert in anchoredChain.chain.validationPath) {
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
        // A certificate-form trust anchor is a CA too: require keyCertSign on it (RFC 5280 6.1.4(n) analog).
        // Skipped when the anchor cert is already part of the chain (allowIncludedTrustAnchor) or absent (key anchor).
        anchoredChain.trustAnchor.cert?.let { anchorCert ->
            if (anchoredChain.chain.none { it == anchorCert }) {
                verifySignatureKeyUsage(anchorCert, context.supportRevocationChecking, certPathLen)
            }
        }
        return checkedCriticalExtensions.mapValues { it.value.toSet() }
    }

    private fun verifySignatureKeyUsage(currCert: X509Certificate, supportRevocationChecking: Boolean, currentCertIndex: Int) {
        if (currCert.findExtension<KeyUsage>()?.keyUsage?.contains(UsageBit.KEY_CERT_SIGN) != true) {
            throw KeyUsageException("Digital signature key usage extension not present at cert index $currentCertIndex.")
        }
        if (supportRevocationChecking && currCert.findExtension<KeyUsage>()?.keyUsage?.contains(UsageBit.CRL_SIGN) != true) {
            throw KeyUsageException("CRL signature key usage extension not present at cert index $currentCertIndex.")
        }
    }

    private fun verifyExpectedEKU(currCert: X509Certificate, expectedEku: Set<ObjectIdentifier>) {
        val eku = currCert.findExtension<ExtendedKeyUsage>()
        if (eku != null && eku.keyUsages.isEmpty()) throw ExtendedKeyUsageException("Empty EKU extension in leaf certificate.")
        for (identifier in expectedEku) {
            if (eku?.keyUsages?.contains(identifier) == false) throw ExtendedKeyUsageException("Missing EKU $identifier in leaf certificate.")
        }
    }
}
