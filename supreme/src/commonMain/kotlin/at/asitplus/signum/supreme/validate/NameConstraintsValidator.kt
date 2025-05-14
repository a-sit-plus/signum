package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.NameConstraintsException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.NameConstraints
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodeNameConstraints
import kotlinx.io.IOException

class NameConstraintsValidator(
    private val pathLength: Int,
    private val currentCertIndex: Int = 0,
    private var previousNameConstraints: NameConstraints? = null
) {

    fun checkNameConstraints(currCert: X509Certificate) {
        if (previousNameConstraints != null && (currentCertIndex == pathLength || !currCert.isSelfIssued())) {

            try {
                if (!previousNameConstraints!!.verify(currCert)) {
                    throw NameConstraintsException("")
                }
            } catch (e: IOException) {
                throw CertificateChainValidatorException(
                    e.message ?: "NameConstraints validation failed."
                )
            }
        }

        previousNameConstraints = mergeNameConstraints(currCert, previousNameConstraints)
    }

    private fun mergeNameConstraints(
        currCert: X509Certificate,
        previousNameConstraints: NameConstraints?
    ): NameConstraints? {

        val newNameConstraints =
            currCert.findExtension(KnownOIDs.nameConstraints_2_5_29_30)?.decodeNameConstraints()

        return if (previousNameConstraints == null) {
            newNameConstraints?.copy()
        } else {
            try {
                previousNameConstraints.merge(newNameConstraints)
            } catch (ioe: IOException) {
                throw NameConstraintsException(ioe.message ?: "NameConstraints merge failed.")
            }
            previousNameConstraints
        }
    }

}