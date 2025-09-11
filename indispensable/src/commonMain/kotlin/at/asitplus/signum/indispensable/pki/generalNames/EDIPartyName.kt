package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException

data class EDIPartyName (
    val value: Asn1ExplicitlyTagged,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.OTHER
): GeneralNameOption, Asn1Encodable<Asn1Element> {
    override fun encodeToTlv() = value

    companion object : Asn1Decodable<Asn1Element, OtherName> {
        override fun doDecode(src: Asn1Element): OtherName {
            if (src !is Asn1ExplicitlyTagged) throw Asn1StructuralException("Invalid ediPartyName Alternative Name found: ${src.toDerHexString()}")

            src.also { it ->
                if (it.children.size > 2) throw Asn1StructuralException("Invalid partyName Alternative Name found (>2 children): ${it.toDerHexString()}")
                if (it.children.find { it.tag.tagValue != GeneralNameOption.NameType.OTHER.value && it.tag.tagValue != GeneralNameOption.NameType.RFC822.value } != null) throw Asn1StructuralException(
                    "Invalid partyName Alternative Name found (illegal implicit tag): ${it.toDerHexString()}"
                )
//                //TODO: strict string parsing
            }
            return OtherName(src)
        }
    }

    override fun toString(): String {
        return value.prettyPrint()
    }


    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is EDIPartyName) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        } else {
            throw UnsupportedOperationException("Narrows, widens and match are not yet implemented for EDIPartyName.")
        }
    }
}