package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.NameConstraintsException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.NameConstraintsExtension
import kotlinx.io.IOException

class NameConstraintsValidator(
    private val pathLength: Int,
    private var currentCertIndex: Int = 0,
    private var previousNameConstraints: NameConstraintsExtension? = null
) : CertificateValidator {

    override suspend fun check(currCert: X509Certificate, remainingCriticalExtensions: MutableSet<ObjectIdentifier>) {
        currentCertIndex++
        if (previousNameConstraints != null && (currentCertIndex == pathLength || !currCert.isSelfIssued())) {

            try {
                if (!previousNameConstraints!!.verify(currCert)) {
                    throw NameConstraintsException("NameConstraints violation at cert index $currentCertIndex")
                }
            } catch (e: IOException) {
                throw CertificateChainValidatorException(
                    e.message ?: "NameConstraints validation failed."
                )
            }
        }
        previousNameConstraints = mergeNameConstraints(currCert, previousNameConstraints)

        remainingCriticalExtensions.remove(KnownOIDs.nameConstraints_2_5_29_30)
    }

    private fun mergeNameConstraints(
        currCert: X509Certificate,
        previousNameConstraints: NameConstraintsExtension?
    ): NameConstraintsExtension? {

        val newNameConstraints =
            currCert.findExtension<NameConstraintsExtension>()

        return if (previousNameConstraints == null) {
            newNameConstraints?.copy()
        } else {
            try {
                previousNameConstraints.mergeWith(newNameConstraints)
            } catch (ioe: IOException) {
                throw NameConstraintsException(ioe.message ?: "NameConstraints merge failed.")
            }
            previousNameConstraints
        }
    }
}