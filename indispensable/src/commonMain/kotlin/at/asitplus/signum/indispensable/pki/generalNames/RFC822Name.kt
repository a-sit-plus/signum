package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.encoding.decodeToIa5String

data class RFC822Name internal constructor(
    val value: Asn1String.IA5,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.RFC822
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    override val isValid: Boolean by lazy { value.isValid }

    /**
     * @throws Asn1Exception if illegal RFC822Name is provided
     */
    @Throws(Asn1Exception::class)
    constructor(value: Asn1String.IA5) : this(
        value,
        GeneralNameOption.NameType.RFC822
    ) {
        if (!isValid) throw Asn1Exception("Invalid RFC822Name.")
    }

    override fun encodeToTlv() = value.encodeToTlv()

    companion object : Asn1Decodable<Asn1Primitive, RFC822Name> {

        private val tag: Asn1Element.Tag = Asn1Element.Tag(1u, false, TagClass.CONTEXT_SPECIFIC)

        override fun doDecode(src: Asn1Primitive): RFC822Name {
            return RFC822Name(src.decodeToIa5String(tag), GeneralNameOption.NameType.RFC822)
        }
    }

    override fun toString(): String {
        return value.value
    }

    @ExperimentalPkiApi
    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            val thisName = value.value.lowercase()
            val inputName = (input as RFC822Name).value.value.lowercase()
            fun isEmailLike(name: String) = '@' in name
            fun hasDomainPrefix(name: String) = name.startsWith(".")

            when {
                thisName == inputName -> GeneralNameOption.ConstraintResult.MATCH

                thisName.endsWith(inputName) -> {
                    when {
                        isEmailLike(inputName) -> GeneralNameOption.ConstraintResult.SAME_TYPE
                        hasDomainPrefix(inputName) -> GeneralNameOption.ConstraintResult.NARROWS
                        thisName.getOrNull(thisName.lastIndexOf(inputName) - 1) == '@' -> GeneralNameOption.ConstraintResult.NARROWS
                        else -> GeneralNameOption.ConstraintResult.SAME_TYPE
                    }
                }

                inputName.endsWith(thisName) -> {
                    when {
                        isEmailLike(thisName) -> GeneralNameOption.ConstraintResult.SAME_TYPE
                        hasDomainPrefix(thisName) -> GeneralNameOption.ConstraintResult.WIDENS
                        inputName.getOrNull(inputName.lastIndexOf(thisName) - 1) == '@' -> GeneralNameOption.ConstraintResult.WIDENS
                        else -> GeneralNameOption.ConstraintResult.SAME_TYPE
                    }
                }

                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }
    }
}