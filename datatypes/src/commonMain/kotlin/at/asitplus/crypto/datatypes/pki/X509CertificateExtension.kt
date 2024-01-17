package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.asn1.*
import kotlinx.serialization.Serializable

/**
 * X.509 Certificate Extension
 */
@Serializable
data class X509CertificateExtension @Throws(Asn1Exception::class) private constructor(
    override val oid: ObjectIdentifier,
    val value: Asn1Element,
    val critical: Boolean = false
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    init {
        if (value.tag != BERTags.OCTET_STRING) throw Asn1TagMismatchException(BERTags.OCTET_STRING, value.tag)
    }

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1EncapsulatingOctetString
    ) : this(oid, value, critical)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1PrimitiveOctetString
    ) : this(oid, value, critical)

    override fun encodeToTlv() = asn1Sequence {
        append(oid)
        if (critical) bool(true)
        append(value)
    }

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): X509CertificateExtension = runRethrowing {

            val id = (src.children[0] as Asn1Primitive).readOid()
            val critical =
                if (src.children[1].tag == BERTags.BOOLEAN) (src.children[1] as Asn1Primitive).content[0] == 0xff.toByte() else false

            val value = src.children.last()
            return X509CertificateExtension(id, value, critical)
        }

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (this::class != other::class) return false

        other as X509CertificateExtension

        if (oid != other.oid) return false
        if (critical != other.critical) return false
        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }
}