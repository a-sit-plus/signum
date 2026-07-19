package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.signum.indispensable.pki.x500.GeneralName.X509Representable.Descriptor
import at.asitplus.signum.indispensable.pki.x500.GeneralName.NameType

/** RFC 5280 `x400Address` GeneralName CHOICE `[3]`. Carries its tagged element verbatim. */
class X400AddressName private constructor(
    val value: Asn1Element,
    override val isValid: Boolean?,
) : AbstractX509GeneralName(NameType.X400, value) {

    constructor(value: Asn1Element) : this(value, null)

    /** Creates an instance with `isValid` determined by [validate]. */
    constructor(value: Asn1Element, validate: (GeneralName) -> Boolean) : this(value, validate(X400AddressName(value)))

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): X400AddressName = X400AddressName(value, validate)

    override fun toString(): String = value.prettyPrint()

    companion object : Descriptor {
        override val type = NameType.X400
        override fun fromAsn1Representation(src: Asn1Element): X400AddressName {
            if (src !is Asn1Sequence) throw Asn1StructuralException("Invalid x400Address Alternative Name found: ${src.toDerHexString()}")
            return X400AddressName(src)
        }
    }
}
