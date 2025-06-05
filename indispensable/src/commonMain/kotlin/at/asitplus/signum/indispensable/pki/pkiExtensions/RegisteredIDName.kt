package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier

class RegisteredIDName (
    val value: ObjectIdentifier,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.OID
): GeneralNameOption, Asn1Encodable<Asn1Primitive> {
    override fun encodeToTlv() = value.encodeToTlv()

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