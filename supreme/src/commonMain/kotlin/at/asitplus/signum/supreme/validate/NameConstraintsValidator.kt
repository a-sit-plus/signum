package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.GeneralNameException
import at.asitplus.signum.NameConstraintsException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.nameConstraints_2_5_29_30
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.NameConstraintsExtension

/**
 * Ensures that each certificate conforms to the permitted and excluded
 * subtrees specified in previous NameConstraints extensions, according to RFC 5280.
 */
class NameConstraintsValidator(
    var startingNameConstraints: NameConstraintsExtension? = null
    ) : CertificateChainValidator {

    override suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext,
        checkedCriticalExtensions: MutableMap<X509Certificate, MutableSet<ObjectIdentifier>>
    ) {
        val certPathLen = chain.size
        var currentCertIndex = 0
        var previousNameConstraints: NameConstraintsExtension? = startingNameConstraints

        for (currCert in chain) {
            checkedCriticalExtensions
                .getOrPut(currCert) { mutableSetOf() }
                .add(KnownOIDs.nameConstraints_2_5_29_30)
            currentCertIndex++

            if (previousNameConstraints?.isValid == false) {
                throw GeneralNameException("Invalid GeneralName in NameConstraints extension.")
            }
            // enforcing that all SANs are valid, since our parsing fails softly
            if (currCert.tbsCertificate.subjectAlternativeNames?.generalNames?.all { it.name.isValid != false } == false) {
                throw GeneralNameException("Invalid GeneralName in Subject Alternative Name at index $currentCertIndex")
            }

            if (previousNameConstraints != null && (currentCertIndex == certPathLen || !currCert.isSelfIssued)) {

                try {
                    if (!previousNameConstraints.verify(currCert, currentCertIndex == certPathLen)) {
                        throw NameConstraintsException("NameConstraints violation at cert index $currentCertIndex")
                    }
                } catch (e: Throwable) {
                    throw CertificateChainValidatorException(
                        e.message ?: "NameConstraints validation failed."
                    )
                }
            }

            if (currentCertIndex == certPathLen &&
                currCert.findExtension<NameConstraintsExtension>() != null) throw NameConstraintsException("Leaf certificate must not contain a NameConstraints extension.")

            previousNameConstraints = mergeNameConstraints(currCert, currentCertIndex, previousNameConstraints)
        }
    }

    @OptIn(ExperimentalPkiApi::class)
    private fun mergeNameConstraints(
        currCert: X509Certificate,
        currentCertIndex: Int,
        previousNameConstraints: NameConstraintsExtension?
    ): NameConstraintsExtension? {

        val newNameConstraints = currCert.findExtension<NameConstraintsExtension>()

        if (newNameConstraints?.critical == false || previousNameConstraints?.critical == false) throw NameConstraintsException("NameConstraints extension is not critical at cert index $currentCertIndex.")

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