package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.extKeyUsage
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import kotlinx.serialization.builtins.ListSerializer
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Extended Key Usage extension: `ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId`.
 * RFC 5280 §4.2.1.12.
 */
class ExtendedKeyUsage internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val keyUsages: Set<ObjectIdentifier>
) : X509CertificateExtension(asn1Representation) {

    /** Builds an Extended Key Usage extension programmatically. Typically non-critical. */
    constructor(keyUsages: Set<ObjectIdentifier>, critical: Boolean = false) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.extKeyUsage,
            critical,
            DER.encodeToByteArray(ListSerializer(ObjectIdentifier.serializer()), keyUsages.toList()),
        ),
        keyUsages,
    )

    companion object : CertificateExtension.Descriptor {
        override val oid get() = KnownOIDs.extKeyUsage

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): ExtendedKeyUsage =
            ExtendedKeyUsage(
                src,
                DER.decodeFromByteArray(ListSerializer(ObjectIdentifier.serializer()), src.value).toSet(),
            )
    }
}
