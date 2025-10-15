package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.Rfc2253Constants

class X500Name internal constructor(
    val relativeDistinguishedNames: List<RelativeDistinguishedName>,
    performValidation: Boolean = false,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.DIRECTORY
) : Asn1Encodable<Asn1Sequence>, GeneralNameOption {

    override val isValid: Boolean by lazy {
        relativeDistinguishedNames.all { it.isValid }
    }

    init {
        if (performValidation && !isValid) throw Asn1Exception("Invalid X500Name.")
    }

    /**
     * @throws Asn1Exception if illegal X500Name is provided
     */
    @Throws(Asn1Exception::class)
    constructor(singleItem: RelativeDistinguishedName) : this(listOf(singleItem))

    /**
     * @throws Asn1Exception if illegal X500Name is provided
     */
    @Throws(Asn1Exception::class)
    constructor(relativeDistinguishedNames: List<RelativeDistinguishedName>) : this(relativeDistinguishedNames, true)

    override fun encodeToTlv() = Asn1.Sequence {
        relativeDistinguishedNames.forEach { +it }
    }

    companion object : Asn1Decodable<Asn1Sequence, X500Name> {
        override fun doDecode(src: Asn1Sequence): X500Name = src.decodeRethrowing {
            buildList {
                while (hasNext()) {
                    add(RelativeDistinguishedName.decodeFromTlv(next().asSet()))
                }
            }.let{ X500Name(it, false) }
        }

        /**
         * Parse an RFC 2253 string (e.g., "CN=John Doe,O=Company,C=US") into an X500Name
         */
        fun fromString(value: String): X500Name {
            if (value.isBlank()) return X500Name(emptyList())

            val delimiterPattern = "[,;]"
            val tokenPattern = """"(?:\\.|[^"\\])*"|\\.|[^"\\,;]+|[,;]"""
            val regex = Regex(tokenPattern)

            return X500Name(
                buildList {
                    var current = buildString { }

                    for (match in regex.findAll(value)) {
                        val token = match.value
                        if (token.length == 1 && token.matches(Regex(delimiterPattern))) {
                            val rdnStr = current.trim()
                            if (rdnStr.isNotEmpty()) add(RelativeDistinguishedName.fromString(rdnStr))
                            current = buildString { } // reset buffer
                        } else {
                            current += token
                        }
                    }

                    val last = current.trim()
                    if (last.isNotEmpty()) add(RelativeDistinguishedName.fromString(last))
                }
            )
        }
    }

    override fun toString() = "X500Name(RDNs=${relativeDistinguishedNames.joinToString()})"



    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            if (this == input) return GeneralNameOption.ConstraintResult.MATCH

            val inputRDNs = (input as X500Name).relativeDistinguishedNames
            val thisRDNs = this.relativeDistinguishedNames

            when {
                inputRDNs.isEmpty() -> GeneralNameOption.ConstraintResult.WIDENS
                thisRDNs.isEmpty() -> GeneralNameOption.ConstraintResult.NARROWS
                this.isWithinSubtree(inputRDNs) -> GeneralNameOption.ConstraintResult.NARROWS
                input.isWithinSubtree(thisRDNs) -> GeneralNameOption.ConstraintResult.WIDENS
                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
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
            rdn.attrsAndValues.joinToString("+") { atv -> atv.toRFC2253String() }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X500Name

        if (isValid != other.isValid) return false
        if (relativeDistinguishedNames != other.relativeDistinguishedNames) return false
        if (type != other.type) return false

        return true
    }

    override fun hashCode(): Int {
        var result = isValid.hashCode()
        result = 31 * result + relativeDistinguishedNames.hashCode()
        result = 31 * result + type.hashCode()
        return result
    }
}