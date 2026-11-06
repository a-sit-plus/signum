package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName.Companion.splitRespectingEscapeAndQuotes

/**
 * An [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) `Name` (the issuer/subject
 * `RDNSequence`), modeled independently of any concrete encoding.
 */
class Name(
    val relativeDistinguishedNames: List<RelativeDistinguishedName>,
    performValidation: Boolean = true
) : WithSourceRepresentation {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()

    val isValid by lazy { relativeDistinguishedNames.all { it.isValid } }
    init { if (performValidation && !isValid) throw Asn1Exception("Invalid Name.") }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Name) return false
        return (relativeDistinguishedNames == other.relativeDistinguishedNames)
    }

    override fun hashCode() =
        relativeDistinguishedNames.hashCode()

    override fun toString() = "Name(RDNs=${relativeDistinguishedNames.joinToString()})"

    fun toRfc2253String(): String =
        relativeDistinguishedNames.asReversed().joinToString(",") { rdn ->
            rdn.attrsAndValues
                .sortedBy { it.oid }
                .joinToString("+") { atv -> atv.toRfc2253String().trim() }
        }

    companion object {
        val EMPTY = Name(emptyList(), false)

        /** Parse an RFC 2253 string (e.g., `CN=John Doe,O=Company,C=US`). */
        fun fromString(value: String): Name {
            if (value.isEmpty()) return EMPTY

            val rdns = value.splitRespectingEscapeAndQuotes(',', ';').map { rdn ->
                require(rdn.isNotBlank()) { "X500Name contains an empty RDN" }
                RelativeDistinguishedName.fromString(rdn.trim())
            }

            // RFC 4514 writes the most-specific RDN first, while ASN.1 RDNSequence stores it last.
            return Name(rdns.asReversed())
        }
    }
}
