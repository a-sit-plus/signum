package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.cidre.IpAddress
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.encoding.decodeToIa5String
import at.asitplus.signum.indispensable.asn1.runRethrowing

data class DNSName internal constructor(
    val value: Asn1String.IA5,
    val allowWildcard: Boolean = true,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.DNS,
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    override val isValid: Boolean by lazy {
        validate(value.value, allowWildcard)
    }

    /**
     * @throws Asn1Exception if illegal DNSName is provided
     */
    @Throws(Asn1Exception::class)
    constructor(value: Asn1String.IA5, allowWildcard: Boolean = true) : this(
        value,
        allowWildcard,
        GeneralNameOption.NameType.DNS
    ) {
        if (!isValid) throw Asn1Exception("Invalid DNSName.")
    }

    override fun encodeToTlv() = value.encodeToTlv()

    companion object : Asn1Decodable<Asn1Primitive, DNSName> {

        private val tag: Asn1Element.Tag = Asn1Element.Tag(2u, false, TagClass.CONTEXT_SPECIFIC)

        override fun doDecode(src: Asn1Primitive): DNSName {
            return runRethrowing {
                DNSName(
                    type = GeneralNameOption.NameType.DNS,
                    value = src.decodeToIa5String(tag),
                )
            }
        }

        private fun validate(value: String, allowWildcard: Boolean): Boolean {
            if (value.isEmpty() || value.contains(' ') || value.startsWith('.') || value.endsWith('.')) {
                return false
            }

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


    override fun toString(): String {
        return value.value
    }

    @ExperimentalPkiApi
    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            val thisName = value.value.lowercase()
            val inputName = (input as DNSName).value.value.lowercase()

            when {
                thisName == inputName -> GeneralNameOption.ConstraintResult.MATCH

                thisName.endsWith(inputName) -> {
                    val index = thisName.lastIndexOf(inputName)
                    val charBefore = thisName.getOrNull(index - 1)
                    val inputStartsWithDot = inputName.startsWith('.')
                    if ((charBefore == '.' && !inputStartsWithDot) || (charBefore != '.' && inputStartsWithDot)) {
                        GeneralNameOption.ConstraintResult.NARROWS
                    } else {
                        GeneralNameOption.ConstraintResult.SAME_TYPE
                    }
                }

                inputName.endsWith(thisName) -> {
                    val index = inputName.lastIndexOf(thisName)
                    val charBefore = inputName.getOrNull(index - 1)
                    val thisStartsWithDot = thisName.startsWith('.')
                    if ((charBefore == '.' && !thisStartsWithDot) || (charBefore != '.' && thisStartsWithDot)) {
                        GeneralNameOption.ConstraintResult.WIDENS
                    } else {
                        GeneralNameOption.ConstraintResult.SAME_TYPE
                    }
                }

                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }
    }
}