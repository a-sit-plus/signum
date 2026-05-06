package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.internals.orLazy
import kotlinx.serialization.KSerializer

class CsrAttribute private constructor(
    providedAsn1Representation: Attribute?,
    providedContent: Pair<ObjectIdentifier, Set<Asn1Element>>?,
) : DerEncodable<Attribute>, Identifiable {

    constructor(id: ObjectIdentifier, value: Set<Asn1Element>) :
        this(null, id to value)

    constructor(id: ObjectIdentifier, value: Asn1Element) : this(id, setOf(value))

    constructor(asn1Representation: Attribute) : this(asn1Representation, null)

    override val asn1Representation: Attribute by providedAsn1Representation orLazy {
        val (oid, value) = requireNotNull(providedContent)
        Attribute(oid, value)
    }

    override val oid: ObjectIdentifier by providedContent?.first orLazy {
        asn1Representation.oid
    }

    val value: Set<Asn1Element> by providedContent?.second orLazy {
        asn1Representation.value
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CsrAttribute) return false
        return oid == other.oid && value == other.value
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }

    override fun toString(): String = "CsrAttribute(oid=$oid, value=$value)"

    companion object : DerDecodable<Attribute, CsrAttribute> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<Attribute>,
            src: Asn1Element,
            der: Der,
        ): CsrAttribute =
            CsrAttribute(der.decodeFromTlv(serializer, src))

       val EXTENSION_REQUEST_OID: ObjectIdentifier = Attribute.EXTENSION_REQUEST_OID
    }
}
