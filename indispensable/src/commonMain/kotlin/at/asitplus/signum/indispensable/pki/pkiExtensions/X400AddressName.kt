package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable

class X400AddressName(
    override val type: GeneralNameOption.NameType,
    val value: Asn1Element
) : GeneralNameOption, Asn1Encodable<Asn1Element> {

    override fun encodeToTlv() = value

    companion object : Asn1Decodable<Asn1Element, X400AddressName> {
        override fun doDecode(src: Asn1Element): X400AddressName {
            return X400AddressName(
                type = GeneralNameOption.NameType.X400, value = src
            )
        }
    }

    override fun constraints(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is X400AddressName) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        } else {
            throw UnsupportedOperationException("Narrows, widens and match are not supported for X400Address in RFC5280.")
        }
    }
}