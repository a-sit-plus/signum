package at.asitplus.signum.supreme.validate

import at.asitplus.signum.BasicConstraintsException
import at.asitplus.signum.KeyUsageException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509KeyUsage
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodeBasicConstraints

class BasicConstraintsValidator(
    private val pathLength: Int,
    private var remainingPathLength: Int? = null,
    private var currentCertIndex: Int = 0
) : Validator {

    override fun check(currCert: X509Certificate) {
        if (currentCertIndex >= pathLength - 1) return

        val basicConstraints =
            currCert.findExtension(KnownOIDs.basicConstraints_2_5_29_19)?.decodeBasicConstraints()
        if (basicConstraints != null && !basicConstraints.ca) {
            throw BasicConstraintsException("Missing CA flag at cert index $currentCertIndex.")
        }

        if (!currCert.tbsCertificate.keyUsage.contains(X509KeyUsage.KEY_CERT_SIGN)) {
            throw KeyUsageException("Digital signature key usage extension not present at cert index $currentCertIndex!")
        }

        if (remainingPathLength != null && !currCert.isSelfIssued()) {
            if (remainingPathLength == 0) {
                throw BasicConstraintsException("pathLenConstraint violated at cert index $currentCertIndex.")
            }
            remainingPathLength = remainingPathLength?.minus(1)
        }

        basicConstraints?.pathLenConstraint?.let { constraint ->
            if (remainingPathLength == null || constraint < remainingPathLength!!) {
                remainingPathLength = constraint
            }
        }

        currentCertIndex++
    }
}