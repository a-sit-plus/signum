package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.KeyUsageException
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsage
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsageExtension
import kotlin.time.Clock
import kotlin.time.Instant

interface CertificateChainValidator {
    suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext,
        checkedCriticalExtensions: MutableMap<X509Certificate, MutableSet<ObjectIdentifier>>
    )
}

@OptIn(ExperimentalPkiApi::class)
class CertificateValidationContext(
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