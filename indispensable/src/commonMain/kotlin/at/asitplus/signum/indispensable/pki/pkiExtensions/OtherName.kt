package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException

class OtherName (
    val value: Asn1ExplicitlyTagged,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.OTHER
): GeneralNameOption, Asn1Encodable<Asn1Element> {

    override fun encodeToTlv() = value

    companion object : Asn1Decodable<Asn1Element, OtherName> {
        override fun doDecode(src: Asn1Element): OtherName {
            // Should be Asn1Sequence but is decoded as Tagged
            if (src !is Asn1ExplicitlyTagged) throw Asn1StructuralException("Invalid otherName Alternative Name found: ${src.toDerHexString()}")

            src.also {
                if (it.children.size != 2) throw Asn1StructuralException("Invalid otherName Alternative Name found (!=2 children): ${it.toDerHexString()}")
                if (it.children.last().tag.tagValue != GeneralNameOption.NameType.OTHER.value) throw Asn1StructuralException(
                    "Invalid otherName Alternative Name found (implicit tag != 0): ${it.toDerHexString()}"
                )
//                ObjectIdentifier.decodeFromAsn1ContentBytes((it.children.first() as Asn1Primitive).content)
            }
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