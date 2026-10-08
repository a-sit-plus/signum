package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable

sealed interface CsrAttribute : Identifiable, Encodable {

    companion object : Decodable<CsrAttribute> {
        operator fun invoke(oid: ObjectIdentifier, value: Set<Asn1Element>): CsrAttribute =
            X509CsrAttribute(oid, value)

        operator fun invoke(oid: ObjectIdentifier, value: Asn1Element): CsrAttribute =
            invoke(oid, setOf(value))

        operator fun invoke(asn1Representation: Pkcs10CsrAttribute): CsrAttribute =
            X509CsrAttribute(asn1Representation)

        @Throws(Asn1Exception::class)
        fun fromAsn1Representation(
            element: Pkcs10CsrAttribute): CsrAttribute =
            X509CsrAttribute(element)

        val EXTENSION_REQUEST_OID: ObjectIdentifier = Pkcs10CsrAttribute.EXTENSION_REQUEST_OID
    }
}

class X509CsrAttribute private constructor(
    override val sourceRepresentation: Pair<Encodable.Representation, Any>?,
    override val oid: ObjectIdentifier,
    val value: Set<Asn1Element>,
) : CsrAttribute {

    constructor(oid: ObjectIdentifier, value: Set<Asn1Element>) : this(null, oid, value)

    constructor(oid: ObjectIdentifier, singleValue: Asn1Element) : this(oid, setOf(singleValue))

    constructor(asn1Representation: Pkcs10CsrAttribute) :
            this(X509 to asn1Representation, asn1Representation.oid, asn1Representation.value)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509CsrAttribute) return false
        return oid == other.oid && value == other.value
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }

    override fun toString(): String = "X509CsrAttribute(oid=$oid, value=$value)"
}
