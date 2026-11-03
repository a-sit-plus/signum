package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.serialization.Asn1Tag

/**
 * Policy Constraints Extension
 * This extension specifies prohibition of policy mappings and requirement that each certificate in
 * the chain has an acceptable policy identifier
 * RFC 5280: 4.2.1.11.
 *
 * A missing `requireExplicitPolicy`/`inhibitPolicyMapping` is represented by `null`.
 * */
data class PolicyConstraints(
    val requireExplicitPolicy: Int? = null,
    val inhibitPolicyMapping: Int? = null,
    override val critical: Boolean = true,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.policyConstraints_2_5_29_36
    }

    init {
        require(requireExplicitPolicy == null || requireExplicitPolicy >= 0)
        require(inhibitPolicyMapping == null || inhibitPolicyMapping >= 0)
    }
}

/**
 * ```
 * PolicyConstraints ::= SEQUENCE {
 *   requireExplicitPolicy [0] SkipCerts OPTIONAL,
 *   inhibitPolicyMapping  [1] SkipCerts OPTIONAL }
 * SkipCerts ::= INTEGER (0..MAX)
 * ```
 * IMPLICIT context-tagged INTEGERs; shared by decode and the programmatic constructor.
 */
@Serializable
internal class PolicyConstraintsBody(
    @Asn1Tag(0u) val requireExplicitPolicy: Asn1Integer? = null,
    @Asn1Tag(1u) val inhibitPolicyMapping: Asn1Integer? = null,
)
