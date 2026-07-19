package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.cidre.IpAddress
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.encoding.decodeToIa5String
import at.asitplus.awesn1.runRethrowing
import at.asitplus.signum.indispensable.pki.x500.GeneralName.ConstraintResult
import at.asitplus.signum.indispensable.pki.x500.GeneralName.X509Representable.Descriptor
import at.asitplus.signum.indispensable.pki.x500.GeneralName.NameType

/** RFC 5280 `dNSName` GeneralName CHOICE `[2]`. */
class DNSName private constructor(
    val value: Asn1String.IA5,
    val allowWildcard: Boolean,
    encoded: Asn1Element,
) : AbstractX509GeneralName(NameType.DNS, encoded) {

    /**
     * @throws Asn1Exception if illegal DNSName is provided
     */
    @Throws(Asn1Exception::class)
    constructor(value: Asn1String.IA5, allowWildcard: Boolean = true)
            : this(value, allowWildcard, value.encodeToTlv() withImplicitTag contextTag(2u)) {
        if (!isValid) throw Asn1Exception("Invalid DNSName.")
    }

    override val isValid: Boolean by lazy { validate(value.value, allowWildcard) }

    override fun toString(): String = value.value

    @ExperimentalPkiApi
    override fun constrains(input: GeneralName?): ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            val thisName = value.value.lowercase()
            val inputName = (input as DNSName).value.value.lowercase()

            when {
                thisName == inputName -> ConstraintResult.MATCH

                thisName.endsWith(inputName) -> {
                    val index = thisName.lastIndexOf(inputName)
                    val charBefore = thisName.getOrNull(index - 1)
                    val inputStartsWithDot = inputName.startsWith('.')
                    if ((charBefore == '.' && !inputStartsWithDot) || (charBefore != '.' && inputStartsWithDot))
                        ConstraintResult.NARROWS else ConstraintResult.SAME_TYPE
                }

                inputName.endsWith(thisName) -> {
                    val index = inputName.lastIndexOf(thisName)
                    val charBefore = inputName.getOrNull(index - 1)
                    val thisStartsWithDot = thisName.startsWith('.')
                    if ((charBefore == '.' && !thisStartsWithDot) || (charBefore != '.' && thisStartsWithDot))
                        ConstraintResult.WIDENS else ConstraintResult.SAME_TYPE
                }

                else -> ConstraintResult.SAME_TYPE
            }
        }
    }

    companion object : Descriptor {
        override val type = NameType.DNS
        private val tag = contextTag(2u)

        override fun fromAsn1Representation(src: Asn1Element): DNSName = runRethrowing {
            DNSName(src.asPrimitive().decodeToIa5String(tag), allowWildcard = true, encoded = src)
        }

        private fun validate(value: String, allowWildcard: Boolean): Boolean {
            if (value.isEmpty() || value.contains(' ') || value.startsWith('.') || value.endsWith('.')) return false

            // check if ip address is encoded as DNSName
            if (value.contains(':')) return false
            if (runCatching { IpAddress(value) }.isSuccess) return false

            var startIndex = 0
            while (startIndex < value.length) {
                val endIndex = value.indexOf('.', startIndex).let { if (it == -1) value.length else it }
                if (endIndex - startIndex < 1) return false

                val firstChar = value[startIndex]

                if (allowWildcard && startIndex == 0 && !firstChar.isLetterOrDigit()) {
                    if (
                        value.length < 3 ||
                        value.indexOf('*') != 0 ||
                        value.getOrNull(startIndex + 1) != '.' ||
                        value.getOrNull(startIndex + 2)?.let { !it.isLetterOrDigit() || it.code >= 128 } == true
                    ) return false
                } else if (!firstChar.isLetterOrDigit()) {
                    return false
                }

                for (i in (startIndex + 1) until endIndex) {
                    val c = value[i]
                    if (!c.isLetterOrDigit() && c != '-') return false
                }

                startIndex = endIndex + 1
            }

            return true
        }
    }
}
