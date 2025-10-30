package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.policyMappings
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Policy Mappings Extension
 * This extension specifies policies that are treated as equivalent between the issuing CA and the subject CA
 * RFC 5280: 4.2.1.5.
 * */
class PolicyMappingsExtension (
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val policyMappings: List<CertificatePolicyMap>
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        policyMappings: List<CertificatePolicyMap>
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), policyMappings)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): PolicyMappingsExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.policyMappings) throw Asn1StructuralException(message = "Expected PolicyMappings extension (OID: ${KnownOIDs.policyMappings}), but found OID: ${base.oid}")

            val inner = base.value.asEncapsulatingOctetString()
                .singleOrNull()
                ?.asSequence()
                ?: return PolicyMappingsExtension(base, emptyList())
            
            val policyMappings = inner.decodeRethrowing {
                buildList {
                    while (hasNext()) {
                        add(CertificatePolicyMap.decodeFromTlv(next().asSequence()))
                    }
                }
            }

            return PolicyMappingsExtension(base, policyMappings)
        }
    }
}

data class CertificatePolicyMap (
    val issuerDomain: ObjectIdentifier,
    val subjectDomain: ObjectIdentifier
): Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +issuerDomain
        +subjectDomain
    }

    companion object : Asn1Decodable<Asn1Sequence, CertificatePolicyMap> {
        override fun doDecode(src: Asn1Sequence): CertificatePolicyMap = src.decodeRethrowing {
            val issuerDomain = next().asPrimitive().readOid()
            val subjectDomain = next().asPrimitive().readOid()
            return CertificatePolicyMap(issuerDomain, subjectDomain)
        }
    }
}
