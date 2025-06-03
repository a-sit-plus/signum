package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509CertificateExtension


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

fun X509CertificateExtension.decodePolicyMappings(): List<CertificatePolicyMap> {
    if (oid != KnownOIDs.policyMappings) throw Asn1StructuralException(message = "This extension is not PolicyMappings extension.")

    val policyMappings = mutableListOf<CertificatePolicyMap>()
    val sequence = value.asEncapsulatingOctetString().children.firstOrNull()?.asSequence()?.children
        ?: return emptyList()
    for (child in sequence) {
        if (child.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, child.tag)
        policyMappings += CertificatePolicyMap.doDecode(child.asSequence())
    }
    return policyMappings
}
