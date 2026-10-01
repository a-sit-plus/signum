package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.CertificateExtensionX509Serializer
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/** Returns null when this extension has no X.509 representation. */
val CertificateExtension.asn1Representation: Awesn1X509CertificateExtension?
    get() = representations[X509] as? Awesn1X509CertificateExtension
        ?: (this as? X509CertificateExtension)?.asn1Representation

val X509CertificateExtension.asn1Representation: Awesn1X509CertificateExtension
    get() = representations[X509] as? Awesn1X509CertificateExtension
        ?: Awesn1X509CertificateExtension(oid, critical, derEncodedValue)

// Compatibility while remaining consumers migrate to format operations.
fun CertificateExtension.encodeToDer(der: Der = DER): ByteArray =
    der.encodeToByteArray(CertificateExtensionX509Serializer, this)
fun CertificateExtension.encodeToTlv(der: Der = DER): Asn1Element =
    der.encodeToTlv(CertificateExtensionX509Serializer, this)
fun CertificateExtension.Companion.decodeFromTlv(src: Awesn1X509CertificateExtension, der: Der = DER): CertificateExtension =
    fromAsn1Representation(src)
fun CertificateExtension.Companion.decodeFromTlv(src: Asn1Element, der: Der = DER): CertificateExtension =
    der.decodeFromTlv(CertificateExtensionX509Serializer, src)
fun CertificateExtension.Companion.decodeFromDer(src: ByteArray, der: Der = DER): CertificateExtension =
    der.decodeFromByteArray(CertificateExtensionX509Serializer, src)

open class X509CertificateExtension private constructor(
    providedAsn1Representation: Awesn1X509CertificateExtension?,
    override val oid: ObjectIdentifier,
    override val critical: Boolean,
    val derEncodedValue: ByteArray,
) : CertificateExtension {


    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: ByteArray,
    ) : this(null, oid, critical, value)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1OctetString,
    ) : this(oid, critical, value.content)

    constructor(asn1Representation: Awesn1X509CertificateExtension) : this(
        asn1Representation,
        asn1Representation.oid,
        asn1Representation.critical,
        asn1Representation.value,
    )

    override val representations: Map<Encodable.Representation, Any> =
        providedAsn1Representation?.let { mapOf(X509 to it) } ?: emptyMap()

    /**
     * The (parsed) ASN.1 structure carried inside this extension's `extnValue` OCTET STRING,
     * i.e. the typed inner value typed extensions decode from.
     */
    val decodedValue: Asn1Element by lazy { Asn1Element.parse(derEncodedValue) }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509CertificateExtension) return false
        return oid == other.oid && critical == other.critical && derEncodedValue.contentEquals(other.derEncodedValue)
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + derEncodedValue.contentHashCode()
        return result
    }

    override fun toString(): String =
        "CertificateExtension(oid=$oid, critical=$critical, value=${derEncodedValue.contentToString()})"
}
