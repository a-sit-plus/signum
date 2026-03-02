package at.asitplus.signum.supreme.validate

import at.asitplus.signum.BasicConstraintsException
import at.asitplus.signum.MissingBasicConstraintsException
import at.asitplus.signum.MissingCaFlagException
import at.asitplus.signum.NonCriticalBasicConstraintsException
import at.asitplus.signum.PathLenConstraintViolationException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension

/**
 * Enforces the X.509 Basic Constraints extension rules for a certificate chain
 */
class BasicConstraintsValidator: CertificateChainValidator {

    override suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext,
        checkedCriticalExtensions: MutableMap<X509Certificate, MutableSet<ObjectIdentifier>>
    ) {
        var remainingPathLength: UInt? = null
        var currentCertIndex = 0
        val certPathLen = chain.size

        for (currCert in chain) {
            checkedCriticalExtensions
                .getOrPut(currCert) { mutableSetOf() }
                .add(KnownOIDs.basicConstraints_2_5_29_19)
            if (currentCertIndex >= certPathLen - 1) break

            currentCertIndex++

            val basicConstraints = currCert.findExtension<BasicConstraintsExtension>()
                ?: throw MissingBasicConstraintsException("Missing basicConstraints extension at cert index $currentCertIndex.")

            checkCaBasicConstraints(currCert, currentCertIndex)

            if (remainingPathLength != null && !currCert.isSelfIssued) {
                if (remainingPathLength.toInt() == 0) {
                    throw PathLenConstraintViolationException("pathLenConstraint violated at cert index $currentCertIndex.")
                }
                remainingPathLength = remainingPathLength.minus(1u)
            }

            basicConstraints.pathLenConstraint.let { constraint ->
                if (remainingPathLength == null || constraint!! < remainingPathLength) {
                    remainingPathLength = constraint
                }
            }
        }
    }
}

@Throws(BasicConstraintsException::class)
fun checkCaBasicConstraints(cert: X509Certificate, certIndex: Int? = null) {
    val location = certIndex?.let { "at cert index $it." } ?: "at trust anchor"
    val basicConstraints = cert.findExtension<BasicConstraintsExtension>()
        ?: throw MissingBasicConstraintsException("Missing basicConstraints extension $location")

    if(!basicConstraints.critical) {
        throw NonCriticalBasicConstraintsException("basicConstraints extension must be critical $location")
    }

    if (!basicConstraints.ca) {
        throw MissingCaFlagException("Missing CA flag $location")
    }
}