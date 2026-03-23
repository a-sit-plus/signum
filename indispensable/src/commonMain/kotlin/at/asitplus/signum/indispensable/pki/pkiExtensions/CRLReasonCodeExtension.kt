package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.cRLReason
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.decodeToEnum
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class CRLReasonCodeExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val reason: CRLReason
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        reason: CRLReason
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), reason)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        override fun doDecode(src: Asn1Sequence): CRLReasonCodeExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.cRLReason) {
                throw Asn1Exception("Expected CRLReason extension, but found OID: ${base.oid}")
            }

            val inner = base.value.asEncapsulatingOctetString()

            return inner.decodeRethrowing {
                val child = next()
                if (child.tag != Asn1Element.Tag.ENUM) {
                    throw Asn1Exception("Expected ENUMERATED tag for CRLReason, but found ${inner.tag}")
                }

                val reason = child.asPrimitive().decodeToEnum<CRLReason>(Asn1Element.Tag.ENUM)

                CRLReasonCodeExtension(base, reason)
            }

        }
    }
}

/**
 * CRLReason ::= ENUMERATED
 * * Note: UNUSED_7 is a placeholder so that the Kotlin ordinals
 * match the RFC 5280 integer values for decodeToEnum().
 */
enum class CRLReason {
    UNSPECIFIED,            // 0
    KEY_COMPROMISE,         // 1
    CA_COMPROMISE,          // 2
    AFFILIATION_CHANGED,    // 3
    SUPERSEDED,             // 4
    CESSATION_OF_OPERATION, // 5
    CERTIFICATE_HOLD,       // 6
    UNUSED_7,               // 7 (Value not used in RFC 5280)
    REMOVE_FROM_CRL,        // 8
    PRIVILEGE_WITHDRAWN,    // 9
    AA_COMPROMISE;          // 10
}