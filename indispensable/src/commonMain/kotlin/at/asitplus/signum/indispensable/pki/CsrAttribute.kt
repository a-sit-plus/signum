package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation

// TODO: properly split this from its asn1 roots
class CsrAttribute(
    override val oid: ObjectIdentifier,
    val value: Set<Asn1Element>
) : Identifiable, WithSourceRepresentation {

    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()

    constructor(oid: ObjectIdentifier, singleValue: Asn1Element) : this(oid, setOf(singleValue))

    constructor(asn1Representation: Pkcs10CsrAttribute) :
            this(asn1Representation.oid, asn1Representation.value)

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

    override fun toString(): String = "X509CsrAttribute(oid=$oid, value=$value)"

    companion object {
        operator fun invoke(oid: ObjectIdentifier, value: Asn1Element): CsrAttribute =
            CsrAttribute(oid, setOf(value))

        val EXTENSION_REQUEST_OID: ObjectIdentifier = Pkcs10CsrAttribute.EXTENSION_REQUEST_OID
    }
}
