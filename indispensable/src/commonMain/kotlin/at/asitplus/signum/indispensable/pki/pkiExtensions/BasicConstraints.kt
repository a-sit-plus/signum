package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class BasicConstraints(
    val ca: Boolean = false,
    val pathLenConstraint: Int
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +ca.encodeToAsn1Primitive()
        +pathLenConstraint.encodeToAsn1Primitive()
    }

    companion object : Asn1Decodable<Asn1Sequence, BasicConstraints> {
        override fun doDecode(src: Asn1Sequence): BasicConstraints {
            var ca = false
            var pathLenConstraint: Int = Int.MAX_VALUE
            if (src.children.isNotEmpty()) ca = src.children[0].asPrimitive().decodeToBoolean()
            if (src.children.size > 1) pathLenConstraint =
                src.children[1].asPrimitive().decodeToInt()
            return BasicConstraints(ca, pathLenConstraint)
        }
    }
}

fun X509CertificateExtension.decodeBasicConstraints(): BasicConstraints {
    if (oid != KnownOIDs.basicConstraints_2_5_29_19) throw Asn1StructuralException(message = "This extension is not BasicConstraints extension.")
    val elem = value.asEncapsulatingOctetString().children.firstOrNull() ?: throw Asn1StructuralException(message = "Not valid BasicConstraints extension.")
    if (elem.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, elem.tag)

    return BasicConstraints.doDecode(elem.asSequence())
}