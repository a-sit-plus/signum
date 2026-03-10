package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate

/**
 * A stateless specialization of [CertificateChainValidator] that applies
 * the same validation logic independently to each certificate in the chain.
 *
 * This interface should be used when validation:
 * - Does not depend on inter-certificate relationships
 * - Does not require state accumulation across the chain
 * - Can be expressed as a pure function of a single certificate
 *
 * The default [validate] implementation iterates over the chain and
 * applies [check] to each certificate.
 */
interface CertificateValidator : CertificateChainValidator {

    /**
     * Performs validation for a single certificate
     * Implementations must return the set of critical extensions
     * that were processed during validation of that certificate
     */
    @ExperimentalPkiApi
    @Throws(Throwable::class)
    suspend fun check(currCert: X509Certificate) : Set<ObjectIdentifier>

    @OptIn(ExperimentalPkiApi::class)
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        val checkedCriticalExtensions = mutableMapOf<X509Certificate, MutableSet<ObjectIdentifier>>()
        anchoredChain.chain.forEachIndexed { index, cert ->
            try {
                val checked = check(cert)
                checkedCriticalExtensions
                    .getOrPut(cert) { mutableSetOf() }
                    .addAll(checked)
            } catch (e: CertificateException) {
                e.certificateIndex = index
                throw e
            }
        }
        return checkedCriticalExtensions.mapValues { it.value.toSet() }
    }
}