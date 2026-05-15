package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.internals.orLazy
import kotlinx.serialization.KSerializer

sealed interface CsrAttribute : Identifiable {

    //prepare for c509, we need a marker
    sealed interface X509Representable : CsrAttribute, DerEncodable<Pkcs10CsrAttribute> {
        val value: Set<Asn1Element>
    }

    companion object : DerDecodable<Pkcs10CsrAttribute, X509Representable> {
        operator fun invoke(oid: ObjectIdentifier, value: Set<Asn1Element>): X509Representable =
            X509CsrAttribute(oid, value)

        operator fun invoke(oid: ObjectIdentifier, value: Asn1Element): X509Representable =
            invoke(oid, setOf(value))

        operator fun invoke(asn1Representation: Pkcs10CsrAttribute): X509Representable =
            X509CsrAttribute(asn1Representation)

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<Pkcs10CsrAttribute>,
            src: Asn1Element,
            der: Der,
        ): X509Representable =
            X509CsrAttribute(der.decodeFromTlv(serializer, src))

        val EXTENSION_REQUEST_OID: ObjectIdentifier = Pkcs10CsrAttribute.EXTENSION_REQUEST_OID
    }
}

abstract class BaseCsrAttribute(
    override val oid: ObjectIdentifier,
) : CsrAttribute {
    override fun toString(): String = "CsrAttribute(oid=$oid)"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CsrAttribute) return false
        return oid == other.oid
    }

    override fun hashCode(): Int = oid.hashCode()
}

class X509CsrAttribute private constructor(
    providedAsn1Representation: Pkcs10CsrAttribute?,
    oid: ObjectIdentifier,
    override val value: Set<Asn1Element>,
) : BaseCsrAttribute(oid), CsrAttribute.X509Representable {

    constructor(oid: ObjectIdentifier, value: Set<Asn1Element>) : this(null, oid, value)

    constructor(oid: ObjectIdentifier, singleValue: Asn1Element) : this(oid, setOf(singleValue))

    constructor(asn1Representation: Pkcs10CsrAttribute) :
            this(asn1Representation, asn1Representation.oid, asn1Representation.value)

    override val asn1Representation: Pkcs10CsrAttribute by providedAsn1Representation orLazy {
        Pkcs10CsrAttribute(oid, value)
    }

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

    override fun toString(): String = "CsrAttribute(oid=$oid, value=$value)"
}

internal fun CsrAttribute.requireX509(): CsrAttribute.X509Representable =
    this as? CsrAttribute.X509Representable
        ?: throw Asn1Exception("CSR attribute $oid has no X.509/DER representation")
