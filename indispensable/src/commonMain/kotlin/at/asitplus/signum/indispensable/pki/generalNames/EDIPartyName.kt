package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException

data class EDIPartyName internal constructor(
    val value: Asn1ExplicitlyTagged,
    override val isValid: Boolean? = null,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.OTHER
): GeneralNameOption, Asn1Encodable<Asn1Element> {

    constructor(value: Asn1ExplicitlyTagged) : this(value, null)

    /**
     * Creates a new [EDIPartyName] instance with validation applied at construction time.
     * This constructor allows supplying a custom [validate] lambda that determines the value of [isValid].
     */
    constructor(value: Asn1ExplicitlyTagged, validate: (GeneralNameOption) -> Boolean) :
            this(value, validate(EDIPartyName(value)))

    override fun encodeToTlv() = value

    companion object : Asn1Decodable<Asn1Element, EDIPartyName> {
        override fun doDecode(src: Asn1Element): EDIPartyName {
            if (src !is Asn1ExplicitlyTagged) throw Asn1StructuralException("Invalid ediPartyName Alternative Name found: ${src.toDerHexString()}")

            src.also { it ->
                if (it.children.size > 2) throw Asn1StructuralException("Invalid partyName Alternative Name found (>2 children): ${it.toDerHexString()}")
                if (it.children.find { it.tag.tagValue != GeneralNameOption.NameType.OTHER.value && it.tag.tagValue != GeneralNameOption.NameType.RFC822.value } != null) throw Asn1StructuralException(
                    "Invalid partyName Alternative Name found (illegal implicit tag): ${it.toDerHexString()}"
                )
            }
            return EDIPartyName(src)
        }
    }

    override fun toString(): String {
        return value.prettyPrint()
    }

    override fun createValidatedCopy(validate: (GeneralNameOption) -> Boolean): EDIPartyName =
        EDIPartyName(value, validate)

}