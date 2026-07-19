package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.encoding.decodeToIa5String
import at.asitplus.signum.indispensable.pki.x500.GeneralName.ConstraintResult
import at.asitplus.signum.indispensable.pki.x500.GeneralName.X509Representable.Descriptor
import at.asitplus.signum.indispensable.pki.x500.GeneralName.NameType

/** RFC 5280 `rfc822Name` GeneralName CHOICE `[1]`. */
class RFC822Name private constructor(
    val value: Asn1String.IA5,
    encoded: Asn1Element,
) : AbstractX509GeneralName(NameType.RFC822, encoded) {

    /**
     * @throws Asn1Exception if illegal RFC822Name is provided
     */
    @Throws(Asn1Exception::class)
    constructor(value: Asn1String.IA5) : this(value, value.encodeToTlv() withImplicitTag contextTag(1u)) {
        if (!isValid) throw Asn1Exception("Invalid RFC822Name.")
    }

    override val isValid: Boolean by lazy { value.isValid && validate() }

    override fun toString(): String = value.value

    private fun validate(): Boolean {
        val str = value.value
        if (str.isEmpty()) return false
        if (str.count { it == '@' } > 1) return false
        val atIndex = str.indexOf('@')
        val domain = if (atIndex >= 0) str.substring(atIndex + 1) else str
        if (domain.isEmpty()) return false
        // Domain may start with '.', but cannot be just '.'
        if (domain.startsWith(".") && domain.length == 1) return false
        return true
    }

    @ExperimentalPkiApi
    override fun constrains(input: GeneralName?): ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            val thisName = value.value.lowercase()
            val inputName = (input as RFC822Name).value.value.lowercase()
            fun isEmailLike(name: String) = '@' in name
            fun hasDomainPrefix(name: String) = name.startsWith(".")

            when {
                thisName == inputName -> ConstraintResult.MATCH

                thisName.endsWith(inputName) -> when {
                    isEmailLike(inputName) -> ConstraintResult.SAME_TYPE
                    hasDomainPrefix(inputName) -> ConstraintResult.NARROWS
                    thisName.getOrNull(thisName.lastIndexOf(inputName) - 1) == '@' -> ConstraintResult.NARROWS
                    else -> ConstraintResult.SAME_TYPE
                }

                inputName.endsWith(thisName) -> when {
                    isEmailLike(thisName) -> ConstraintResult.SAME_TYPE
                    hasDomainPrefix(thisName) -> ConstraintResult.WIDENS
                    inputName.getOrNull(inputName.lastIndexOf(thisName) - 1) == '@' -> ConstraintResult.WIDENS
                    else -> ConstraintResult.SAME_TYPE
                }

                else -> ConstraintResult.SAME_TYPE
            }
        }
    }

    companion object : Descriptor {
        override val type = NameType.RFC822
        private val tag = contextTag(1u)
        override fun fromAsn1Representation(src: Asn1Element): RFC822Name =
            RFC822Name(src.asPrimitive().decodeToIa5String(tag), src)
    }
}
