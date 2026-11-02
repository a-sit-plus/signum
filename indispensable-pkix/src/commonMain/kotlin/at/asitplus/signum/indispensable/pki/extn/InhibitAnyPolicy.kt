package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.inhibitAnyPolicy
import at.asitplus.awesn1.encoding.decodeToAsn1Integer
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.toBigInteger
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Inhibit Any-Policy Extension
 * This extension specifies the number of certs allowed in a chain before anyPolicy is no longer permitted
 * RFC 5280: 4.2.1.14.
 * */
class InhibitAnyPolicy internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val skipCerts: Int
) : X509CertificateExtension(asn1Representation) {

    /** Builds an Inhibit anyPolicy extension programmatically. MUST be critical (RFC 5280 §4.2.1.14). */
    constructor(skipCerts: Int, critical: Boolean = true) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.inhibitAnyPolicy,
            critical,
            Asn1Integer(skipCerts).encodeToTlv().derEncoded,
        ),
        skipCerts,
    )

    companion object : CertificateExtension.Descriptor {
        override val oid get() = KnownOIDs.inhibitAnyPolicy

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): InhibitAnyPolicy {
            val value = Asn1Element.parse(src.value)
                .asPrimitive()
                .decodeToAsn1Integer()
                .toBigInteger()
                .intValue()

            return InhibitAnyPolicy(src, value)
        }
    }
}
