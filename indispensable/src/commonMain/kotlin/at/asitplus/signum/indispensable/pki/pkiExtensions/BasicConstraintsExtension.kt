package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUInt
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Basic Constraints Extension
 * RFC 5280: 4.2.1.9.
 * Defines is the subject of the cert CA and how deep a cert path may exist through that CA
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

        override fun doDecode(src: Asn1Sequence): BasicConstraintsExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.basicConstraints_2_5_29_19) throw Asn1StructuralException(message = "Expected BasicConstraints extension (OID: ${KnownOIDs.basicConstraints_2_5_29_19}), but found OID: ${base.oid}")

            val inner = base.value.asEncapsulatingOctetString().single().asSequence()

            val (ca, pathLenConstraint) = inner.decodeRethrowing {
                val ca = nextOrNull()?.asPrimitive()?.decodeToBoolean() ?: false
                val pathLenConstraint = nextOrNull()
                    ?.asPrimitive()
                    ?.decodeToUInt()
                    ?: if (ca) UInt.MAX_VALUE else null
                ca to pathLenConstraint
            }

            return BasicConstraintsExtension(base, ca, pathLenConstraint)
        }
    }
}