package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException

data class X400AddressName internal constructor(
    val value: Asn1Element,
    override val isValid: Boolean? = null,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.X400,
) : GeneralNameOption, Asn1Encodable<Asn1Element> {

    constructor(value: Asn1Element) : this(value, null)

    /**
     * Creates a new [X400AddressName] instance with validation applied at construction time.
     * This constructor allows supplying a custom [validate] lambda that determines the value of [isValid].
     */
    constructor(value: Asn1Element, validate: (GeneralNameOption) -> Boolean) :
            this(value, validate(X400AddressName(value)))

    override fun encodeToTlv() = value

    companion object : Asn1Decodable<Asn1Element, X400AddressName> {
        override fun doDecode(src: Asn1Element): X400AddressName {
            if (src !is Asn1Sequence) throw Asn1StructuralException("Invalid x400Address Alternative Name found: ${src.toDerHexString()}")
            return X400AddressName(src)
        }
    }

    override fun toString(): String {
        return value.prettyPrint()
    }

    override fun createValidatedCopy(validate: (GeneralNameOption) -> Boolean): X400AddressName =
        X400AddressName(value, validate)

}