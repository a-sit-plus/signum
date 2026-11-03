package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.Signum

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.policyMappings
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Policy Mappings Extension
 * This extension specifies policies that are treated as equivalent between the issuing CA and the subject CA
 * RFC 5280: 4.2.1.5.
 * */
class PolicyMappings internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val policyMappings: List<CertificatePolicyMap>,
    sourceRepresentation: Pair<Encodable.Representation, Any>? = X509 to asn1Representation,
) : X509CertificateExtension(
    sourceRepresentation, asn1Representation.oid, asn1Representation.critical, asn1Representation.value,
) {

    /** Builds a Policy Mappings extension programmatically. SHOULD be critical (RFC 5280 §4.2.1.5). */
    constructor(
        policyMappings: List<CertificatePolicyMap>,
        critical: Boolean = true,
    ) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.policyMappings,
            critical,
                        Signum.Der.encodeToByteArray(ListSerializer(CertificatePolicyMap.serializer()), policyMappings),
        ),
        policyMappings,
        sourceRepresentation = null,
    )

    companion object : CertificateExtension.Descriptor<PolicyMappings>{
        override val oid get() = KnownOIDs.policyMappings

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): PolicyMappings {
            val policyMappings =
                                Signum.Der.decodeFromByteArray(ListSerializer(CertificatePolicyMap.serializer()), src.value)
            return PolicyMappings(src, policyMappings)
        }
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
