package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1String
import kotlinx.io.IOException

class DNSName(
    val value: Asn1String.IA5,
    allowWildcard: Boolean = false,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.DNS,
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    private val alphaDigits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    init {
        val name = value.value

        if (name.isEmpty()) {
            throw IOException("DNSName must not be null or empty")
        }

        if (name.contains(' ')) {
            throw IOException("DNSName with blank components is not permitted")
        }

        if (name.startsWith('.') || name.endsWith('.')) {
            throw IOException("DNSName may not begin or end with a .")
        }

        var startIndex = 0
        while (startIndex < name.length) {
            val endIndex = name.indexOf('.', startIndex).let { if (it == -1) name.length else it }

            if (endIndex - startIndex < 1) {
                throw IOException("DNSName with empty components is not permitted")
            }

            if (allowWildcard) {
                val firstChar = name[startIndex]
                if (alphaDigits.indexOf(firstChar) < 0) {
                    if (
                        name.length < 3 ||
                        name.indexOf('*') != 0 ||
                        name.getOrNull(startIndex + 1) != '.' ||
                        alphaDigits.indexOf(name.getOrNull(startIndex + 2) ?: ' ') < 0
                    ) {
                        throw IOException(
                            "DNSName components must begin with a letter, digit, " +
                                    "or the first component can have only a wildcard character *"
                        )
                    }
                }
            } else {
                val firstChar = name[startIndex]
                if (alphaDigits.indexOf(firstChar) < 0) {
                    throw IOException("DNSName components must begin with a letter or digit")
                }
            }

            for (i in (startIndex + 1) until endIndex) {
                val c = name[i]
                if (alphaDigits.indexOf(c) < 0 && c != '-') {
                    throw IOException("DNSName components must consist of letters, digits, and hyphens")
                }
            }

            startIndex = endIndex + 1
        }
    }


    override fun encodeToTlv() = value.encodeToTlv()

    companion object : Asn1Decodable<Asn1Primitive, DNSName> {
        override fun doDecode(src: Asn1Primitive): DNSName {
            return DNSName(
                type = GeneralNameOption.NameType.DNS,
                value = Asn1String.IA5(src.asAsn1String().value)
            )
        }
    }

    override fun constraints(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is DNSName) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        }

        val thisName = value.value.lowercase()
        val inputName = input.value.value.lowercase()

        if (thisName == inputName) {
            return GeneralNameOption.ConstraintResult.MATCH
        }

        if (thisName.endsWith(inputName)) {
            val index = thisName.lastIndexOf(inputName)
            val charBefore = thisName.getOrNull(index - 1)
            val inputStartsWithDot = inputName.startsWith('.')
            if ((charBefore == '.' && !inputStartsWithDot) || (charBefore != '.' && inputStartsWithDot)) {
                return GeneralNameOption.ConstraintResult.WIDENS
            }
            return GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        if (inputName.endsWith(thisName)) {
            val index = inputName.lastIndexOf(thisName)
            val charBefore = inputName.getOrNull(index - 1)
            val thisStartsWithDot = thisName.startsWith('.')
            if ((charBefore == '.' && !thisStartsWithDot) || (charBefore != '.' && thisStartsWithDot)) {
                return GeneralNameOption.ConstraintResult.NARROWS
            }
            return GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        return GeneralNameOption.ConstraintResult.SAME_TYPE
    }
}