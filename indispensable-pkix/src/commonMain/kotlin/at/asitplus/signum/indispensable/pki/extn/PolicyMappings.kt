package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.policyMappings
import at.asitplus.awesn1.serialization.DER
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
    val policyMappings: List<CertificatePolicyMap>
) : X509CertificateExtension(asn1Representation) {

    /** Builds a Policy Mappings extension programmatically. SHOULD be critical (RFC 5280 §4.2.1.5). */
    constructor(
        policyMappings: List<CertificatePolicyMap>,
        critical: Boolean = true,
    ) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.policyMappings,
            critical,
            DER.encodeToByteArray(ListSerializer(CertificatePolicyMap.serializer()), policyMappings),
        ),
        policyMappings,
    )

    companion object : CertificateExtension.Descriptor {
        override val oid get() = KnownOIDs.policyMappings

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): PolicyMappings {
            val policyMappings = runCatching {
                DER.decodeFromByteArray(ListSerializer(CertificatePolicyMap.serializer()), src.value)
            }.getOrDefault(emptyList())
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
