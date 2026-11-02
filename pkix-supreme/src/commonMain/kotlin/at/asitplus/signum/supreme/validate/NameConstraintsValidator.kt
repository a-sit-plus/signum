package at.asitplus.signum.supreme.validate
import at.asitplus.signum.indispensable.pki.findExtension

import at.asitplus.signum.indispensable.pki.CertificateChainValidatorException
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.GeneralNameException
import at.asitplus.signum.indispensable.pki.NameConstraintsException
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.nameConstraints_2_5_29_30
import at.asitplus.awesn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.extn.NameConstraints
import at.asitplus.signum.indispensable.pki.validationPath
/**
 * Ensures that each certificate conforms to the permitted and excluded
 * subtrees specified in previous NameConstraints extensions, according to RFC 5280.
 *
 * [RFC 5280 6.1.3(b)-(c), 6.1.4(g)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3).
 * Anchor constraints are used as initial inputs (an allowed local choice under
 * [RFC 6818 section 4](https://www.rfc-editor.org/rfc/rfc6818.html#section-4)).
 */
class NameConstraintsValidator: CertificateChainValidator {

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        val certPathLen = anchoredChain.chain.size
        var currentCertIndex = 0
        var previousNameConstraints = anchoredChain.trustAnchor.nameConstraints
        val checkedCriticalExtensions = mutableMapOf<X509Certificate, MutableSet<ObjectIdentifier>>()

        for (currCert in anchoredChain.chain.validationPath) {
            checkedCriticalExtensions
                .getOrPut(currCert) { mutableSetOf() }
                .addAll(setOf(KnownOIDs.nameConstraints_2_5_29_30, KnownOIDs.subjectAltName_2_5_29_17))
            val originalIndex = certPathLen - 1 - currentCertIndex
            currentCertIndex++

            if (previousNameConstraints?.isValid == false) {
                throw GeneralNameException("Invalid GeneralName in NameConstraints extension.")
            }
            // enforcing that all SANs are valid, since our parsing fails softly
            if (currCert.tbsCertificate.subjectAlternativeNames?.generalNames?.all { it.isValid != false } == false) {
                throw GeneralNameException("Invalid GeneralName in Subject Alternative Name at index $originalIndex")
            }

            if (previousNameConstraints != null && (currentCertIndex == certPathLen || !currCert.isSelfIssued)) {

                try {
                    if (!previousNameConstraints.verify(currCert, currentCertIndex == certPathLen)) {
                        throw NameConstraintsException("NameConstraints violation at cert index $originalIndex")
                    }
                } catch (e: Throwable) {
                    throw CertificateChainValidatorException(
                        e.message ?: "NameConstraints validation failed."
                    )
                }
            }

            // Section 6.1.4 prepares the next certificate; target constraints have no descendants here.
            if (currentCertIndex != certPathLen) {
                previousNameConstraints = mergeNameConstraints(currCert, previousNameConstraints)
            }
        }

        return checkedCriticalExtensions.mapValues { it.value.toSet() }
    }

    @OptIn(ExperimentalPkiApi::class)
    private fun mergeNameConstraints(
        currCert: X509Certificate,
        previousNameConstraints: NameConstraints?
    ): NameConstraints? {

        val newNameConstraints = currCert.findExtension<NameConstraints>()

        // 6.1.4(g) processes recognized constraints regardless of criticality. The MUST mark critical
        // in 4.2.1.10 is an issuance-profile requirement, not an extra basic-path check.

        return try {
            // previous == null: adopt the cert's constraints; mergedWith(null) returns previous
            previousNameConstraints?.mergedWith(newNameConstraints) ?: newNameConstraints?.copy()
        } catch (e: Throwable) {
            throw NameConstraintsException(e.message ?: "NameConstraints merge failed.")
        }
    }
}
