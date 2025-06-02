package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

fun X509CertificateExtension.decodeInhibitAnyPolicy() : Int {
    if (oid != KnownOIDs.inhibitAnyPolicy) throw Asn1StructuralException(message = "This extension is not InhibitAnyPolicy extension.")
    val elem = value.asEncapsulatingOctetString().children.firstOrNull() ?: throw Asn1StructuralException(message = "Not valid InhibitAnyPolicy extension.")
    if (elem.tag != Asn1Element.Tag.INT) throw Asn1TagMismatchException(Asn1Element.Tag.INT, elem.tag)

    return Asn1Integer.doDecode(elem.asPrimitive()).toBigInteger().intValue()
}