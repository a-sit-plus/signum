package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CertificateValidityException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.NameConstraintsException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.generalNames.IPAddressName
import at.asitplus.signum.indispensable.pki.pkiExtensions.NameConstraintsExtension
import kotlinx.io.IOException

/**
 * Ensures that each certificate conforms to the permitted and excluded
 * subtrees specified in previous NameConstraints extensions, according to RFC 5280.
 */
class NameConstraintsValidator(
    private val pathLength: Int,
    private var currentCertIndex: Int = 0,
    var previousNameConstraints: NameConstraintsExtension? = null
) : CertificateValidator {

    @ExperimentalPkiApi
    override suspend fun check(currCert: X509Certificate, remainingCriticalExtensions: MutableSet<ObjectIdentifier>) {
        remainingCriticalExtensions.remove(KnownOIDs.nameConstraints_2_5_29_30)
        currentCertIndex++

        if (previousNameConstraints?.isValid == false) {
            throw NameConstraintsException("Invalid GeneralName in NameConstraints extension.")
        }
        // enforcing that all SANs are valid, since our parsing fails softly
        if (currCert.tbsCertificate.subjectAlternativeNames?.generalNames?.all { it.name.isValid != false } == false) {
            throw CertificateValidityException("Invalid GeneralName in Subject Alternative Name at index $currentCertIndex")
        }

        if (previousNameConstraints != null && (currentCertIndex == pathLength || !currCert.isSelfIssued)) {

            try {
                if (!previousNameConstraints!!.verify(currCert, currentCertIndex == pathLength)) {
                    throw NameConstraintsException("NameConstraints violation at cert index $currentCertIndex")
                }
            } catch (e: Throwable) {
                throw CertificateChainValidatorException(
                    e.message ?: "NameConstraints validation failed."
                )
            }
        }

        if (currentCertIndex == pathLength &&
            currCert.findExtension<NameConstraintsExtension>() != null) throw NameConstraintsException("Leaf certificate must not contain a NameConstraints extension.")

        previousNameConstraints = mergeNameConstraints(currCert, previousNameConstraints)

    }

    @OptIn(ExperimentalPkiApi::class)
    private fun mergeNameConstraints(
        currCert: X509Certificate,
        previousNameConstraints: NameConstraintsExtension?
    ): NameConstraintsExtension? {

        val newNameConstraints = currCert.findExtension<NameConstraintsExtension>()

        if (newNameConstraints?.critical == false || previousNameConstraints?.critical == false) throw NameConstraintsException("NameConstraints extension is not critical.")

        return if (previousNameConstraints == null) {
            newNameConstraints?.copy()
        } else {
            try {
                previousNameConstraints.mergeWith(newNameConstraints)
            } catch (e: Throwable) {
                throw NameConstraintsException(e.message ?: "NameConstraints merge failed.")
            }
            previousNameConstraints
        }
    }
}