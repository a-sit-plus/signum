package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier

data class RegisteredIDName (
    val value: ObjectIdentifier,
    override val performValidation: Boolean = false,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.OID
): GeneralNameOption, Asn1Encodable<Asn1Primitive> {
    override fun encodeToTlv() = value.encodeToTlv()

    /**
     * RegisteredIDName is always valid since ObjectIdentifier
     * is guaranteed to be valid by its constructor.
     * */
    override val isValid: Boolean = true

    companion object : Asn1Decodable<Asn1Primitive, RegisteredIDName> {
        override fun doDecode(src: Asn1Primitive): RegisteredIDName {
            return RegisteredIDName(ObjectIdentifier.decodeFromAsn1ContentBytes((src).content))
        }
    }

    override fun toString(): String {
        return value.toString()
    }

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is RegisteredIDName) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        } else {
            throw UnsupportedOperationException("Narrows, widens and match are not yet implemented for RegisteredIDName.")
        }
    }
}