package at.asitplus.signum.supreme.validate
import at.asitplus.signum.indispensable.pki.findExtension

import at.asitplus.signum.indispensable.pki.BasicConstraintsException
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.MissingBasicConstraintsException
import at.asitplus.signum.indispensable.pki.MissingCaFlagException
import at.asitplus.signum.indispensable.pki.NonCriticalBasicConstraintsException
import at.asitplus.signum.indispensable.pki.PathLenConstraintViolationException
import at.asitplus.awesn1.*
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.extn.BasicConstraints
import at.asitplus.signum.indispensable.pki.validationPath

/**
 * Checks path CAs under [RFC 5280 6.1.4(k)-(m)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4).
 * Trust anchors are inputs, not path certificates (6.1.1(d)). Section 4.2.1.9's issuance requirement
 * to mark basicConstraints critical is not an additional section 6.1 path check.
 */
class BasicConstraintsValidator: CertificateChainValidator {

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        var remainingPathLength: UInt? = null
        var currentCertIndex = 0
        val processingChain = anchoredChain.chain
        val certPathLen = processingChain.size
        val checkedCriticalExtensions = mutableMapOf<X509Certificate, MutableSet<ObjectIdentifier>>()
        for (currCert in processingChain.validationPath) {
            checkedCriticalExtensions
                .getOrPut(currCert) { mutableSetOf() }
                .add(KnownOIDs.basicConstraints_2_5_29_19)
            if (currentCertIndex >= certPathLen - 1) break
            val originalIndex = certPathLen - 1 - currentCertIndex
            currentCertIndex++

            val basicConstraints = currCert.findExtension<BasicConstraints>()
                ?: throw MissingBasicConstraintsException("Missing basicConstraints extension at cert index $originalIndex.")

            if (!basicConstraints.ca) throw MissingCaFlagException("Missing CA flag at cert index $originalIndex.")

            if (remainingPathLength != null && !currCert.isSelfIssued) {
                if (remainingPathLength.toInt() == 0) {
                    throw PathLenConstraintViolationException("pathLenConstraint violated at cert index $originalIndex.")
                }
                remainingPathLength = remainingPathLength.minus(1u)
            }

            basicConstraints.pathLenConstraint?.let { constraint ->
                // RFC 5280 6.1.4(l)/(m): max_path_length may only shrink
                if (remainingPathLength == null || constraint < remainingPathLength) {
                    remainingPathLength = constraint
                }
            }
        }
        return checkedCriticalExtensions.mapValues { it.value.toSet() }
    }
}

/** Optional CA issuance-profile check: [RFC 5280 4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9). */
@Throws(BasicConstraintsException::class)
fun checkCaBasicConstraints(cert: X509Certificate, certIndex: Int? = null) {
    val location = certIndex?.let { "at cert index $it." } ?: "at trust anchor"
    val basicConstraints = cert.findExtension<BasicConstraints>()
        ?: throw MissingBasicConstraintsException("Missing basicConstraints extension $location")

    if(!basicConstraints.critical) {
        throw NonCriticalBasicConstraintsException("basicConstraints extension must be critical $location")
    }

    if (!basicConstraints.ca) {
        throw MissingCaFlagException("Missing CA flag $location")
    }
}
