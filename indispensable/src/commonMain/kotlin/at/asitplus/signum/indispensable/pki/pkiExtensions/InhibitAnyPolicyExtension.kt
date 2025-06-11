package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class InhibitAnyPolicyExtension(
    override val oid: ObjectIdentifier,
    override val critical: Boolean,
    override val value: Asn1EncapsulatingOctetString,
    val skipCerts: Int
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        skipCerts: Int,
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), skipCerts)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): InhibitAnyPolicyExtension {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.inhibitAnyPolicy) throw Asn1StructuralException(message = "This extension is not InhibitAnyPolicy extension.")
            val inner = base.value.asEncapsulatingOctetString().children.firstOrNull()
                ?: throw Asn1StructuralException(message = "Not valid InhibitAnyPolicy extension.")
            if (inner.tag != Asn1Element.Tag.INT) throw Asn1TagMismatchException(
                Asn1Element.Tag.INT,
                inner.tag
            )

            return InhibitAnyPolicyExtension(
                base,
                Asn1Integer.doDecode(inner.asPrimitive()).toBigInteger().intValue()
            )
        }
    }
}