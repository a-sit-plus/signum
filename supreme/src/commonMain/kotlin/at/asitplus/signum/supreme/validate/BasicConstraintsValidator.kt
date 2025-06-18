package at.asitplus.signum.supreme.validate

import at.asitplus.signum.BasicConstraintsException
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension

class BasicConstraintsValidator(
    private val pathLength: Int,
    private var remainingPathLength: UInt? = null,
    private var currentCertIndex: Int = 0
) : Validator {

    override fun check(currCert: X509Certificate) {
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