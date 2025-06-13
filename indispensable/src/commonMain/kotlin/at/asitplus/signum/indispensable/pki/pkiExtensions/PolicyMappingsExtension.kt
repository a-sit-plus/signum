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
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Policy Mappings Extension
 * This extension specifies policies that are treated as equivalent between the issuing CA and the subject CA
 * RFC 5280: 4.2.1.5.
 * */
data class PolicyMappingsExtension (
    override val oid: ObjectIdentifier,
    override val critical: Boolean,
    override val value: Asn1EncapsulatingOctetString,
    val policyMappings: List<CertificatePolicyMap>
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        policyMappings: List<CertificatePolicyMap>
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), policyMappings)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): PolicyMappingsExtension {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.policyMappings) throw Asn1StructuralException(message = "This extension is not PolicyMappings extension.")

            val inner = base.value.asEncapsulatingOctetString()
                .nextChildOrNull()
                ?.takeIf { it.tag == Asn1Element.Tag.SEQUENCE }
                ?.asSequence()
                ?: return PolicyMappingsExtension(base, emptyList())
            
            val policyMappings = buildList {
                while (inner.hasMoreChildren()) {
                    val child = inner.nextChild()
                    if (child.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, child.tag)
                    add(CertificatePolicyMap.decodeFromTlv(child.asSequence()))
                }
            }

            return PolicyMappingsExtension(base, policyMappings)
        }
    }
}

class CertificatePolicyMap (
    val issuerDomain: ObjectIdentifier,
    val subjectDomain: ObjectIdentifier
): Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +issuerDomain
        +subjectDomain
    }

    companion object : Asn1Decodable<Asn1Sequence, CertificatePolicyMap> {
        override fun doDecode(src: Asn1Sequence): CertificatePolicyMap {
            val issuerDomain = src.nextChild().asPrimitive().readOid()
            val subjectDomain = src.nextChild().asPrimitive().readOid()
            return CertificatePolicyMap(issuerDomain, subjectDomain)
        }
    }
}
