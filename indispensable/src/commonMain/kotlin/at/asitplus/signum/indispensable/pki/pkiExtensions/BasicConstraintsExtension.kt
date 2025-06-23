package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUInt
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Basic Constraints Extension
 * RFC 5280: 4.2.1.9.
*/
class BasicConstraintsExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
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

            if (base.oid != KnownOIDs.basicConstraints_2_5_29_19) throw Asn1StructuralException(message = "This extension is not BasicConstraints extension.")

            val inner = base.value.asEncapsulatingOctetString()
                .nextChildOrNull()
                ?.takeIf { it.tag == Asn1Element.Tag.SEQUENCE }
                ?.asSequence()
                ?: throw Asn1StructuralException("Invalid or missing SEQUENCE in BasicConstraints extension.")


            val ca = inner.nextChildOrNull()?.asPrimitive()?.decodeToBoolean() ?: false
            val pathLenConstraint = inner.nextChildOrNull()
                ?.asPrimitive()
                ?.decodeToUInt()
                ?: if (ca) UInt.MAX_VALUE else null

            if (inner.hasMoreChildren()) throw Asn1StructuralException("Invalid BasicConstraintsExtension found (>2 children): ${inner.toDerHexString()}")

            return BasicConstraintsExtension(base, ca, pathLenConstraint)
        }
    }
}