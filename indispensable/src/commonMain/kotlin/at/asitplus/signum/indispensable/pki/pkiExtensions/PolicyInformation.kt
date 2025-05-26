package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class PolicyInformation(
    override val oid: ObjectIdentifier,
    val policyQualifiers: Set<PolicyQualifierInfo>
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        if (policyQualifiers.isNotEmpty()) {
            +Asn1.Sequence {
                for (qualifier in policyQualifiers) {
                    +qualifier
                }
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, PolicyInformation> {
        override fun doDecode(src: Asn1Sequence) : PolicyInformation {
            val id = (src.children[0].asPrimitive()).readOid()
            val policyQualifiers = mutableSetOf<PolicyQualifierInfo>()

            if (src.children.size > 1) {
                if (src.children[1].tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, src.children[1].tag)
                val qualifiersSequence = src.children[1].asSequence()
                for (child in qualifiersSequence.children) {
                    if (child.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, child.tag)
                    policyQualifiers += PolicyQualifierInfo.doDecode(child.asSequence())
                }
            }
            return PolicyInformation(id, policyQualifiers)
        }
    }
}

// TODO further decoding of value (User notice, CPS Pointer etc.)
class PolicyQualifierInfo(
    override val oid: ObjectIdentifier,
    val value: Asn1Element
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        +value
    }

    companion object : Asn1Decodable<Asn1Sequence, PolicyQualifierInfo> {
        override fun doDecode(src: Asn1Sequence) : PolicyQualifierInfo {
            val id = (src.children[0].asPrimitive()).readOid()
            val value = src.children.last()
            return  PolicyQualifierInfo(id, value)
        }
    }
}

fun X509CertificateExtension.decodeCertificatePolicies(): List<PolicyInformation> {
    if (oid != KnownOIDs.certificatePolicies_2_5_29_32) throw Asn1StructuralException(message = "This extension is not CertificatePolicies extension.")
    if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, value.tag)

    val policyInformation = mutableListOf<PolicyInformation>()
    val sequence = value.asEncapsulatingOctetString().children.firstOrNull()?.asSequence()?.children
        ?: return emptyList()
    for (child in sequence) {
        if (child.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, child.tag)
        policyInformation += PolicyInformation.doDecode(child.asSequence())
    }
    return policyInformation
}