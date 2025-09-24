package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException

data class OtherName (
    val value: Asn1ExplicitlyTagged,
    override val performValidation: Boolean = false,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.OTHER
): GeneralNameOption, Asn1Encodable<Asn1Element> {

    /**
     * Always `null`, since no validation logic is implemented
     */
    override val isValid: Boolean? = null

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

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is X400AddressName) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        } else {
            throw UnsupportedOperationException("Narrows, widens and match are not yet implemented for OtherName.")
        }
    }
}