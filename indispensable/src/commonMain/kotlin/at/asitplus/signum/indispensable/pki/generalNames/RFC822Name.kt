package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToIa5String

class RFC822Name(
    val value: Asn1String.IA5,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.RFC822
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    override fun encodeToTlv() = value.encodeToTlv()

    companion object : Asn1Decodable<Asn1Primitive, RFC822Name> {

        private val tag: Asn1Element.Tag = Asn1Element.Tag(1u, false)

        override fun doDecode(src: Asn1Primitive): RFC822Name {
            return RFC822Name(src.decodeToIa5String(tag))
        }
    }

    override fun toString(): String {
        return value.value
    }

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is RFC822Name) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        }

        val thisName = value.value.lowercase()
        val inputName = input.value.value.lowercase()

        if (thisName == inputName) {
            return GeneralNameOption.ConstraintResult.MATCH
        }

        fun isEmailLike(name: String) = '@' in name
        fun hasDomainPrefix(name: String) = name.startsWith(".")

        if (thisName.endsWith(inputName)) {
            return when {
                isEmailLike(inputName) -> GeneralNameOption.ConstraintResult.SAME_TYPE
                hasDomainPrefix(inputName) -> GeneralNameOption.ConstraintResult.WIDENS
                thisName.getOrNull(thisName.lastIndexOf(inputName) - 1) == '@' -> GeneralNameOption.ConstraintResult.WIDENS
                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }

        if (inputName.endsWith(thisName)) {
            return when {
                isEmailLike(thisName) -> GeneralNameOption.ConstraintResult.SAME_TYPE
                hasDomainPrefix(thisName) -> GeneralNameOption.ConstraintResult.NARROWS
                inputName.getOrNull(inputName.lastIndexOf(thisName) - 1) == '@' -> GeneralNameOption.ConstraintResult.NARROWS
                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }

        return GeneralNameOption.ConstraintResult.SAME_TYPE
    }
}