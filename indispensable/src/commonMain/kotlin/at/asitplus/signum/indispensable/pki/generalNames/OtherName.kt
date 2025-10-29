package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException

@OptIn(ExperimentalPkiApi::class)
data class OtherName internal constructor(
    val value: Asn1ExplicitlyTagged,
    override val isValid: Boolean? = null,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.OTHER
): GeneralNameOption, Asn1Encodable<Asn1Element> {

    constructor(value: Asn1ExplicitlyTagged) : this(value, null)

    /**
     * Creates a new [OtherName] instance with validation applied at construction time.
     * This constructor allows supplying a custom [validate] lambda that determines the value of [isValid].
     */
    constructor(value: Asn1ExplicitlyTagged, validate: (GeneralNameOption) -> Boolean) :
            this(value, validate(OtherName(value)))

    override fun encodeToTlv() = value

    companion object : Asn1Decodable<Asn1Element, OtherName> {
        override fun doDecode(src: Asn1Element): OtherName {
            if (src !is Asn1ExplicitlyTagged) throw Asn1StructuralException("Invalid otherName Alternative Name found: ${src.toDerHexString()}")
            if (src.children.size != 2) throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${src.toDerHexString()}")

            return OtherName(src)
        }
    }

    override fun toString(): String {
        return value.prettyPrint()
    }

    override fun createValidatedCopy(validate: (GeneralNameOption) -> Boolean): OtherName =
        OtherName(value, validate)

}