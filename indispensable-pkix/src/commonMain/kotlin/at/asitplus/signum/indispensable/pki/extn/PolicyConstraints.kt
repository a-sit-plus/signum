package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.policyConstraints_2_5_29_36
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Policy Constraints Extension
 * This extension specifies prohibition of policy mappings and requirement that each certificate in
 * the chain has an acceptable policy identifier
 * RFC 5280: 4.2.1.11.
 *
 * A missing `requireExplicitPolicy`/`inhibitPolicyMapping` is represented by the sentinel `-1`.
 * */
class PolicyConstraints internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val requireExplicitPolicy: Asn1Integer,
    val inhibitPolicyMapping: Asn1Integer
) : X509CertificateExtension(asn1Representation) {

    /**
     * Builds a Policy Constraints extension programmatically. `null` means the respective field is absent.
     * MUST be critical (RFC 5280 §4.2.1.11).
     */
    constructor(
        requireExplicitPolicy: Int? = null,
        inhibitPolicyMapping: Int? = null,
        critical: Boolean = true,
    ) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.policyConstraints_2_5_29_36,
            critical,
            DER.encodeToByteArray(
                PolicyConstraintsBody.serializer(),
                PolicyConstraintsBody(
                    requireExplicitPolicy?.let { Asn1Integer(it) },
                    inhibitPolicyMapping?.let { Asn1Integer(it) },
                ),
            ),
        ),
        requireExplicitPolicy?.let { Asn1Integer(it) } ?: Asn1Integer.fromDecimalString("-1"),
        inhibitPolicyMapping?.let { Asn1Integer(it) } ?: Asn1Integer.fromDecimalString("-1"),
    )

    companion object : CertificateExtension.Descriptor {
        override val oid get() = KnownOIDs.policyConstraints_2_5_29_36

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): PolicyConstraints {
            val body = DER.decodeFromByteArray(PolicyConstraintsBody.serializer(), src.value)
            return PolicyConstraints(
                src,
                body.requireExplicitPolicy ?: Asn1Integer.fromDecimalString("-1"),
                body.inhibitPolicyMapping ?: Asn1Integer.fromDecimalString("-1"),
            )
        }
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
private class PolicyConstraintsBody(
    @Asn1Tag(0u) val requireExplicitPolicy: Asn1Integer? = null,
    @Asn1Tag(1u) val inhibitPolicyMapping: Asn1Integer? = null,
)
