package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.BasicConstraintsException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension

class BasicConstraintsValidator(
    private val pathLength: Int,
    private var remainingPathLength: UInt? = null,
    private var currentCertIndex: Int = 0
) : CertificateValidator {

    override suspend fun check(currCert: X509Certificate, remainingCriticalExtensions: MutableSet<ObjectIdentifier>) {
        remainingCriticalExtensions.remove(KnownOIDs.basicConstraints_2_5_29_19)
        if (currentCertIndex >= pathLength - 1) return

        val basicConstraints = currCert.findExtension<BasicConstraintsExtension>()
            ?: throw BasicConstraintsException("Missing basicConstraints extension at cert index $currentCertIndex.")

        require(basicConstraints.critical) {
            throw BasicConstraintsException("basicConstraints extension must be critical (index $currentCertIndex).")
        }

        if (!basicConstraints.ca) {
            throw BasicConstraintsException("Missing CA flag at cert index $currentCertIndex.")
        }

        if (remainingPathLength != null && !currCert.isSelfIssued()) {
            if (remainingPathLength?.toInt() == 0) {
                throw BasicConstraintsException("pathLenConstraint violated at cert index $currentCertIndex.")
            }
            remainingPathLength = remainingPathLength?.minus(1u)
        }

        basicConstraints.pathLenConstraint.let { constraint ->
            if (remainingPathLength == null || constraint!! < remainingPathLength!!) {
                remainingPathLength = constraint
            }
        }

        currentCertIndex++
    }
}