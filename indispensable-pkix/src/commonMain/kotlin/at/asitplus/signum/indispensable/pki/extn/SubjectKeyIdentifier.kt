package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.encoding.encodeToAsn1OctetStringPrimitive
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.subjectKeyIdentifier
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Subject Key Identifier extension: `SubjectKeyIdentifier ::= KeyIdentifier` (an OCTET STRING).
 * RFC 5280 §4.2.1.2 — MUST be non-critical.
 */
class SubjectKeyIdentifier internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val keyIdentifier: ByteArray?
) : X509CertificateExtension(asn1Representation) {

    /** Builds a Subject Key Identifier extension programmatically from a raw [keyIdentifier]. */
    constructor(keyIdentifier: ByteArray, critical: Boolean = false) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.subjectKeyIdentifier,
            critical,
            keyIdentifier.encodeToAsn1OctetStringPrimitive().derEncoded,
        ),
        keyIdentifier,
    )

    companion object : CertificateExtension.Descriptor {
        override val oid get() = KnownOIDs.subjectKeyIdentifier

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): SubjectKeyIdentifier {
            val keyIdentifier = Asn1Element.parse(src.value).asPrimitive().content

            return SubjectKeyIdentifier(src, keyIdentifier)
        }
    }
}
