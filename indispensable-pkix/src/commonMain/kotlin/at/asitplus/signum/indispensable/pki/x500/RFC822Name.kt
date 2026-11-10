package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.x500.ConstraintResult

/** RFC 5280 `rfc822Name` GeneralName CHOICE `[1]`. */
class RFC822Name(
    val value: String,
) : AbstractGeneralName() {
    override val equalityValue get() = value

    init {
        if (!value.all { it.code < 128 } || !validate()) throw Asn1Exception("Invalid RFC822Name.")
    }

    override fun toString(): String = value

    private fun validate(): Boolean {
        val str = value
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
            val thisName = value.lowercase()
            val inputName = (input as RFC822Name).value.lowercase()
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

    companion object {
        operator fun invoke(value: Asn1String.IA5): RFC822Name = RFC822Name(value.value)

        val tag = X509GeneralName.Tags.rfc822Name
        internal fun fromAsn1Model(src: X509GeneralName): RFC822Name =
            RFC822Name((src as X509GeneralName.Rfc822).value)
    }
}
