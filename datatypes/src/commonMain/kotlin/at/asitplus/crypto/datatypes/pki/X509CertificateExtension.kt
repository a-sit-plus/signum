package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

@Serializable
data class X509CertificateExtension(
    val id: ObjectIdentifier, val critical: Boolean = false,
    @Serializable(with = ByteArrayBase64Serializer::class) val value: ByteArray
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = asn1Sequence {
        oid { id }
        if (critical) bool { true }
        octetString { value }
    }

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        override fun decodeFromTlv(src: Asn1Sequence): X509CertificateExtension {

            val id = (src.children[0] as Asn1Primitive).readOid()
            val critical =
                if (src.children[1].tag == BERTags.BOOLEAN) (src.children[1] as Asn1Primitive).content[0] == 0xff.toByte() else false

            val value = (src.children.last() as Asn1Primitive).decode(BERTags.OCTET_STRING) { it }
            return X509CertificateExtension(id, critical, value)
        }

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (this::class != other::class) return false

        other as X509CertificateExtension

        if (id != other.id) return false
        if (critical != other.critical) return false
        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }
}