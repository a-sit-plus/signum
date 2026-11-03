package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum
import at.asitplus.awesn1.*
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Certificate extension independent of its encoding format
 */
interface CertificateExtension : Identifiable, Encodable {

    val critical: Boolean

    /**
     * Describes a typed [CertificateExtension] extension and knows how to construct it from its
     * generic awesn1 representation. Mirrors [AttributeTypeAndValue.Descriptor]; register custom
     * extension types via [Signum.register].
     */
    interface Descriptor<out T : CertificateExtension> : Decodable<T>, Identifiable {
        fun fromAsn1Representation(src: Awesn1X509CertificateExtension): T
    }


    companion object : Decodable<CertificateExtension> {
        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: ByteArray,
        ): CertificateExtension = X509CertificateExtension(oid, critical, value)

        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: Asn1OctetString,
        ): CertificateExtension = X509CertificateExtension(oid, critical, value)

        operator fun invoke(asn1Representation: Awesn1X509CertificateExtension): CertificateExtension =
            fromAsn1Representation(asn1Representation)

        /**
         * Upgrades the generic awesn1 [src] extension to a registered typed extension (e.g. a
         * `KeyUsageExtension` from `indispensable-pkix`) when a [Descriptor] is registered for its
         * OID, falling back to a generic [X509CertificateExtension] only for unknown OIDs. Failures of
         * a known typed extension propagate; malformed bodies must not become absent constraints.
         */
        fun fromAsn1Representation(src: Awesn1X509CertificateExtension): CertificateExtension =
            Signum.certificateExtensionDescriptorFor(src.oid)?.let { descriptor ->
                descriptor.fromAsn1Representation(src)
            } ?: X509CertificateExtension(src)

    }
}
