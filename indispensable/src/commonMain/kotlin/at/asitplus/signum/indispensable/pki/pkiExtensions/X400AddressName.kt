package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException

class X400AddressName(
    val value: Asn1Element,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.X400,
) : GeneralNameOption, Asn1Encodable<Asn1Element> {

    override fun encodeToTlv() = value

    companion object : Asn1Decodable<Asn1Element, X400AddressName> {
        override fun doDecode(src: Asn1Element): X400AddressName {
            if (src !is Asn1Sequence) throw Asn1StructuralException("Invalid x400Address Alternative Name found: ${src.toDerHexString()}")
            //TODO: strict structural parsing
            return X400AddressName(src)
        }
    }

    override fun toString(): String {
        return value.prettyPrint()
    }

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is X400AddressName) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        } else {
            throw UnsupportedOperationException("Narrows, widens and match are not supported for X400Address in RFC5280.")
        }
    }
}