package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1ExplicitlyTagged
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.signum.indispensable.pki.x500.GeneralName.X509Representable.Descriptor
import at.asitplus.signum.indispensable.pki.x500.GeneralName.NameType

/** RFC 5280 `otherName` GeneralName CHOICE `[0]`. Carries its tagged element verbatim. */
class OtherName private constructor(
    val value: Asn1ExplicitlyTagged,
    override val isValid: Boolean?,
) : AbstractX509GeneralName(NameType.OTHER, value) {

    constructor(value: Asn1ExplicitlyTagged) : this(value, null)

    /** Creates an instance with `isValid` determined by [validate]. */
    constructor(value: Asn1ExplicitlyTagged, validate: (GeneralName) -> Boolean) : this(value, validate(OtherName(value)))

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): OtherName = OtherName(value, validate)

    override fun toString(): String = value.prettyPrint()

    companion object : Descriptor {
        override val type = NameType.OTHER
        override fun fromAsn1Representation(src: Asn1Element): OtherName {
            if (src !is Asn1ExplicitlyTagged) throw Asn1StructuralException("Invalid otherName Alternative Name found: ${src.toDerHexString()}")
            if (src.children.size != 2) throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${src.toDerHexString()}")
            return OtherName(src)
        }
    }
}
