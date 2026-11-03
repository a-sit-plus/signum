package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension
import kotlinx.serialization.Serializable

/**
 * Policy Mappings Extension
 * This extension specifies policies that are treated as equivalent between the issuing CA and the subject CA
 * RFC 5280: 4.2.1.5.
 * */
data class PolicyMappings(
    val policyMappings: List<CertificatePolicyMap>,
    override val critical: Boolean = true,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.policyMappings
    }
}

/**
 * A single `PolicyMapping` entry:
 * ```
 * SEQUENCE { issuerDomainPolicy CertPolicyId, subjectDomainPolicy CertPolicyId }
 * ```
 */
@Serializable
data class CertificatePolicyMap(
    val issuerDomain: ObjectIdentifier,
    val subjectDomain: ObjectIdentifier,
)
