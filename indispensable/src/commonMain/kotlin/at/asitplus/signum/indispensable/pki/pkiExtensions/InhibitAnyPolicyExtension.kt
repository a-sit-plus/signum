package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Inhibit Any-Policy Extension
 * This extension specifies the number of certs allowed in a chain before anyPolicy is no longer permitted
 * RFC 5280: 4.2.1.14.
 * */
class InhibitAnyPolicyExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
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

            val primitive = base.value.asEncapsulatingOctetString()
                .nextChildOrNull()
                ?.takeIf { it.tag == Asn1Element.Tag.INT }
                ?.asPrimitive()
                ?: throw Asn1StructuralException("Invalid or missing PRIMITIVE in InhibitAnyPolicy extension.")

            return InhibitAnyPolicyExtension(
                base,
                Asn1Integer.decodeFromTlv(primitive).toBigInteger().intValue()
            )
        }
    }
}