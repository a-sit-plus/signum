package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUInt
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
* Basic Constraints Extension
*/
class BasicConstraintsExtension(
    override val oid: ObjectIdentifier,
    override val critical: Boolean,
    override val value: Asn1EncapsulatingOctetString,
    val ca: Boolean,
    val pathLenConstraint: UInt?
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        ca: Boolean,
        pathLenConstraint: UInt?
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), ca, pathLenConstraint)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): BasicConstraintsExtension {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.basicConstraints_2_5_29_19) {
                throw Asn1StructuralException(message = "This extension is not BasicConstraints extension.")
            }

            val inner = base.value.asEncapsulatingOctetString().children.firstOrNull()
                ?: throw Asn1StructuralException(message = "Not valid BasicConstraints extension.")

            if (inner.tag != Asn1Element.Tag.SEQUENCE) {
                throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, inner.tag)
            }

            val seqInner = inner.asSequence()
            val ca = seqInner.children.getOrNull(0)?.asPrimitive()?.decodeToBoolean() ?: false
            val pathLenConstraint = when {
                seqInner.children.size > 1 -> seqInner.children[1].asPrimitive().decodeToUInt()
                ca -> UInt.MAX_VALUE
                else -> null
            }

            return BasicConstraintsExtension(base, ca, pathLenConstraint)
        }
    }
}