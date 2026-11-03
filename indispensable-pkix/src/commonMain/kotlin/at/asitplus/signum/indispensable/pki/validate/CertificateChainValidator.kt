package at.asitplus.signum.indispensable.pki.validate


import at.asitplus.signum.indispensable.pki.TrustAnchor

import at.asitplus.signum.indispensable.pki.CertificateException
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Performs validation on a complete certificate chain.
 *
 * Implementations receive the entire [AnchoredCertificateChain] and are responsible
 * for performing all necessary validation steps in a single invocation.
 *
 * If trust anchor validation is not required, [AnchoredCertificateChain.trustAnchor] can be ignored
 *
 * Validators are expected to be immutable and stateless. Any state required
 * for validation must be derived from the provided inputs.
 *
 * Implementation must return the set of critical extensions that were processed during validation for each certificate, or an empty set if none were processed.
 *
 * @throws CertificateException If the certificate fails validation according to the rules implemented by this validator
 * @throws CancellationException
 * @throws Throwable For multiplatform safety (e.g., Kotlin/Native to Swift), this allows catching all exceptions without crashing the application.
 */
interface CertificateChainValidator {
    @ExperimentalPkiApi
    @Throws(Throwable::class)
    suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>>
}

@OptIn(ExperimentalPkiApi::class)
data class CertificateValidationContext(
    val date: Instant = Clock.System.now(),
    val explicitPolicyRequired: Boolean = false,
    val policyMappingInhibited: Boolean = false,
    val anyPolicyInhibited: Boolean = false,
    val policyQualifiersRejected: Boolean = false,
    val initialPolicies: Set<ObjectIdentifier> = emptySet(),
    val allowIncludedTrustAnchor: Boolean = true,
    val trustAnchors: Set<TrustAnchor> ,
    /**
     * Caller-requested leaf purposes, checked if EKU is present. Absence is unrestricted; applications
     * may separately require presence: [RFC 5280 4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12).
     * Does not impose TLS EKU restrictions on intermediate CAs.
     */
    val expectedEku: Set<ObjectIdentifier> = emptySet(),
    /** Additional application-specific leaf KU policy; basic path validation imposes none by default. */
    val leafKeyUsageCheck: suspend (X509Certificate) -> Unit = {},
    /**
     * Additional cRLSign check on path CAs with KU. This is NOT revocation checking: no CRLs/OCSP
     * are obtained or checked. RFC 5280 6.3.3(f) concerns the actual CRL signer, not every path CA.
     */
    val supportRevocationChecking: Boolean = false
)
