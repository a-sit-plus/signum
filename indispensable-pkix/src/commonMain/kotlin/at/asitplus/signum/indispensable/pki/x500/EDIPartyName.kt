package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1ExplicitlyTagged
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.signum.indispensable.pki.x500.GeneralName.X509Representable.Descriptor
import at.asitplus.signum.indispensable.pki.x500.GeneralName.NameType

/** RFC 5280 `ediPartyName` GeneralName CHOICE `[5]`. Carries its tagged element verbatim. */
class EDIPartyName private constructor(
    val value: Asn1ExplicitlyTagged,
    override val isValid: Boolean?,
) : AbstractX509GeneralName(NameType.EDI, value) {

    constructor(value: Asn1ExplicitlyTagged) : this(value, null)

    /** Creates an instance with `isValid` determined by [validate]. */
    constructor(value: Asn1ExplicitlyTagged, validate: (GeneralName) -> Boolean) : this(value, validate(EDIPartyName(value)))

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): EDIPartyName = EDIPartyName(value, validate)

    override fun toString(): String = value.prettyPrint()

    companion object : Descriptor {
        override val type = NameType.EDI
        override fun fromAsn1Representation(src: Asn1Element): EDIPartyName {
            if (src !is Asn1ExplicitlyTagged) throw Asn1StructuralException("Invalid ediPartyName Alternative Name found: ${src.toDerHexString()}")
            src.also {
                if (it.children.size > 2) throw Asn1StructuralException("Invalid partyName Alternative Name found (>2 children): ${it.toDerHexString()}")
                if (it.children.find { c -> c.tag.tagValue != NameType.OTHER.value && c.tag.tagValue != NameType.RFC822.value } != null)
                    throw Asn1StructuralException("Invalid partyName Alternative Name found (illegal implicit tag): ${it.toDerHexString()}")
            }
            return EDIPartyName(src)
        }
    }
}
