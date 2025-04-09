package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import kotlinx.serialization.Serializable

data class Pkcs10CertificationRequestAttribute(
    override val oid: ObjectIdentifier,
    val value: List<Asn1Element>
) : Asn1Encodable<Asn1Sequence>, Identifiable {
    constructor(id: ObjectIdentifier, value: Asn1Element) : this(id, listOf(value))

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        +Asn1.Set { value.forEach { +it } }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (this::class != other::class) return false

        other as Pkcs10CertificationRequestAttribute

        if (oid != other.oid) return false
        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, Pkcs10CertificationRequestAttribute> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Pkcs10CertificationRequestAttribute = runRethrowing {
            val id = (src.children[0] as Asn1Primitive).readOid()
            val value = (src.children.last() as Asn1Set).children
            return Pkcs10CertificationRequestAttribute(id, value)
        }
    }
}