package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Bool

/**
 * X.509 Certificate Extension
 */
@ConsistentCopyVisibility
data class X509CertificateExtension @Throws(Asn1Exception::class) constructor(
    override val oid: ObjectIdentifier,
    val value: Asn1Element,
    val critical: Boolean = false
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    init {
        if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, value.tag)
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

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        if (critical) +Bool(true)
        +value
    }

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {

            val id = next().asPrimitive().readOid()
            val critical =
                if (src.children[1].tag == Asn1Element.Tag.BOOL) next().asPrimitive().content[0] == 0xff.toByte() else false

            val value = next()
            X509CertificateExtension(id, value, critical)
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