package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName.Companion.splitRespectingEscapeAndQuotes
import at.asitplus.awesn1.crypto.pki.X500Name as Asn1X500Name

/**
 * An [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) `Name` (the issuer/subject
 * `RDNSequence`), modeled independently of any concrete encoding.
 *
 * The logical content — an ordered list of [RelativeDistinguishedName]s — is shared across
 * encodings. The DER/X.509 serialization is [Name] (implemented by
 * [X500Name]); a future C509/CBOR serialization
 * would add a sibling representation carrying the same [relativeDistinguishedNames]. This mirrors
 * the [CsrAttribute]/[AlternativeNames] pattern: the data classes stay encoding-agnostic, and the
 * X.509 specialization carries the awesn1 backing.
 */
interface Name : Encodable {

    val relativeDistinguishedNames: List<RelativeDistinguishedName>

}

/**
 * The DER/X.509 specialization of [Name] (an X.500 directory name) — a certificate issuer/subject.
 * RFC 2253 parsing/printing remains in Signum, while the structural representation comes from awesn1.
 */
class X500Name internal constructor(
    override val relativeDistinguishedNames: List<RelativeDistinguishedName>,
    performValidation: Boolean,
    override val sourceRepresentation: Pair<Encodable.Representation, Any>?,
) : Name {

    constructor(relativeDistinguishedNames: List<RelativeDistinguishedName>, performValidation: Boolean) :
        this(relativeDistinguishedNames, performValidation, null)

    val isValid: Boolean by lazy {
        relativeDistinguishedNames.all { it.isValid }
    }

    init {
        if (performValidation && !isValid) throw Asn1Exception("Invalid X500Name.")
    }

    @Throws(Asn1Exception::class)
    constructor(singleItem: RelativeDistinguishedName) : this(listOf(singleItem))

    @Throws(Asn1Exception::class)
    constructor(relativeDistinguishedNames: List<RelativeDistinguishedName>) : this(relativeDistinguishedNames, true)

    @Throws(Asn1Exception::class)
    constructor(singleAttribute: X500AttributeTypeAndValue) : this(RelativeDistinguishedName(singleAttribute))

    companion object : Decodable<X500Name> {
        val EMPTY = X500Name(emptyList(), false)

        fun fromAsn1Representation(
            element: Asn1X500Name): X500Name = X500Name(
            element
                .map { RelativeDistinguishedName(it) }, false, X509 to element)

        /** Parse an RFC 2253 string (e.g., `CN=John Doe,O=Company,C=US`). */
        fun fromString(value: String): X500Name {
            if (value.isEmpty()) return X500Name(emptyList())

            val rdns = value.splitRespectingEscapeAndQuotes(',', ';').map { rdn ->
                require(rdn.isNotBlank()) { "X500Name contains an empty RDN" }
                RelativeDistinguishedName.fromString(rdn.trim())
            }

            // RFC 4514 writes the most-specific RDN first, while ASN.1 RDNSequence stores it last.
            return X500Name(rdns.asReversed())
        }
    }

    override fun toString() = "X500Name(RDNs=${relativeDistinguishedNames.joinToString()})"

    fun toRfc2253String(): String =
        relativeDistinguishedNames.asReversed().joinToString(",") { rdn ->
            rdn.attrsAndValues
                .sortedBy { it.oid }
                .joinToString("+") { atv -> atv.toRfc2253String().trim() }
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X500Name
        return isValid == other.isValid && relativeDistinguishedNames == other.relativeDistinguishedNames
    }

    override fun hashCode(): Int = 31 * isValid.hashCode() + relativeDistinguishedNames.hashCode()
}
