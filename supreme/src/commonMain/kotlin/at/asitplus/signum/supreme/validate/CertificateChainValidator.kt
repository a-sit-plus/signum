package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.KeyUsageException
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsage
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsageExtension
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
    val trustAnchors: Set<TrustAnchor> = SystemTrustStore,
    val expectedEku: Set<ObjectIdentifier> = emptySet(),
    /** use this lambda to specify how to handle leaf key usage check */
    val leafKeyUsageCheck: suspend (X509Certificate) -> Unit = { currCert ->
        val basicConstraints = currCert.findExtension<BasicConstraintsExtension>()

        if (basicConstraints?.ca == true) {
            if (currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.KEY_CERT_SIGN) != true) {
                throw KeyUsageException("Digital signature key usage extension not present at leaf cert.")
            }
        }

        if (basicConstraints?.ca != true && currCert.findExtension<KeyUsageExtension>()?.keyUsage?.contains(KeyUsage.KEY_CERT_SIGN) == true) {
            throw KeyUsageException("Digital signature key usage extension must not be present at leaf cert.")
        }
    },
    val supportRevocationChecking: Boolean = false
)