package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName

data class X500Name(
    val relativeDistinguishedNames: List<RelativeDistinguishedName>,
    override val performValidation: Boolean = false,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.DIRECTORY
) : Asn1Encodable<Asn1Sequence>, GeneralNameOption {

    /**
     * Always `null`, since no validation logic is implemented
     */
    override val isValid: Boolean? = null

    constructor(singleItem: RelativeDistinguishedName) : this(listOf(singleItem))

    override fun encodeToTlv() = Asn1.Sequence {
        relativeDistinguishedNames.forEach { +it }
    }

    companion object : Asn1Decodable<Asn1Sequence, X500Name> {
        override fun doDecode(src: Asn1Sequence): X500Name = src.decodeRethrowing {
            buildList {
                while (hasNext()) {
                    add(RelativeDistinguishedName.decodeFromTlv(next().asSet()))
                }
            }.let(::X500Name)
        }

        /**
         * Parse an RFC 2253 string (e.g., "CN=John Doe,O=Company,C=US") into an X500Name
         */
        fun fromString(value: String): X500Name {
            val rdns = mutableListOf<RelativeDistinguishedName>()
            var start = 0
            var i = 0
            var inEscape = false

            while (i < value.length) {
                val c = value[i]
                when {
                    inEscape -> inEscape = false
                    c == '\\' -> inEscape = true
                    c == ',' || c == ';' -> {
                        val rdnStr = value.substring(start, i).trim()
                        if (rdnStr.isNotEmpty()) rdns.add(RelativeDistinguishedName.fromString(rdnStr))
                        start = i + 1
                    }
                }
                i++
            }

            // Last RDN
            val lastRdn = value.substring(start).trim()
            if (lastRdn.isNotEmpty()) rdns.add(RelativeDistinguishedName.fromString(lastRdn))

            return X500Name(rdns)
        }
    }

    override fun toString() = "X500Name(RDNs=${relativeDistinguishedNames.joinToString()})"

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is X500Name) return GeneralNameOption.ConstraintResult.DIFF_TYPE

        if (this == input) return GeneralNameOption.ConstraintResult.MATCH

        val inputRDNs = input.relativeDistinguishedNames
        val thisRDNs = this.relativeDistinguishedNames

        return when {
            inputRDNs.isEmpty() -> GeneralNameOption.ConstraintResult.WIDENS
            thisRDNs.isEmpty() -> GeneralNameOption.ConstraintResult.NARROWS
            this.isWithinSubtree(inputRDNs) -> GeneralNameOption.ConstraintResult.NARROWS
            input.isWithinSubtree(thisRDNs) -> GeneralNameOption.ConstraintResult.WIDENS
            else -> GeneralNameOption.ConstraintResult.SAME_TYPE
        }
    }

    private fun isWithinSubtree(otherRDNs: List<RelativeDistinguishedName>): Boolean {
        if (this.relativeDistinguishedNames == otherRDNs) return true
        if (otherRDNs.isEmpty()) return true
        if (this.relativeDistinguishedNames.size < otherRDNs.size) return false

        for (i in otherRDNs.indices) {
            if (this.relativeDistinguishedNames[i] != otherRDNs[i]) return false
        }

        return true
    }

    fun toRfc2253String(): String {
        return relativeDistinguishedNames.joinToString(",") { rdn ->
            rdn.sortedAttrsAndValues.joinToString("+") { atv -> atv.toRFC2253String() }
        }
    }
}