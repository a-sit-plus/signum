package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500Name as Asn1X500Name
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer

/**
 * An [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) `Name` (the issuer/subject
 * `RDNSequence`), modeled independently of any concrete encoding.
 *
 * The logical content — an ordered list of [RelativeDistinguishedName]s — is shared across
 * encodings. The DER/X.509 serialization is [X509Representable] (implemented by
 * [X500Name]); a future C509/CBOR serialization
 * would add a sibling representation carrying the same [relativeDistinguishedNames]. This mirrors
 * the [CsrAttribute]/[AlternativeNames] pattern: the data classes stay encoding-agnostic, and the
 * X.509 specialization carries the awesn1 backing.
 */
interface Name {

    val relativeDistinguishedNames: List<RelativeDistinguishedName>

    /**
     * A [Name] that has a DER/X.509 representation, backed by awesn1's [Asn1X500Name].
     */
    interface X509Representable : Name, DerEncodable<Asn1X500Name>
}

internal fun Name.requireX509(): Name.X509Representable =
    this as? Name.X509Representable
        ?: throw Asn1Exception("Name has no X.509/DER representation")

/**
 * The DER/X.509 specialization of [Name] (an X.500 directory name) — a certificate issuer/subject.
 * RFC 2253 parsing/printing remains in Signum, while the structural representation comes from awesn1.
 */
class X500Name(
    override val relativeDistinguishedNames: List<RelativeDistinguishedName>,
    performValidation: Boolean,
) : Name.X509Representable {

    override val asn1Representation: Asn1X500Name
        get() = relativeDistinguishedNames.map { it.asn1Representation }

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

    companion object : DerDecodable<Asn1X500Name, X500Name> {
        /** The RDNSequence serializer (`SEQUENCE OF RelativeDistinguishedName`). */
        val serializer: KSerializer<Asn1X500Name> =
            ListSerializer(X500RelativeDistinguishedName.serializer())

        override fun decodeFromTlv(
            serializer: KSerializer<Asn1X500Name>,
            src: Asn1Element,
            der: Der,
        ): X500Name = X500Name(der.decodeFromTlv(serializer, src).map { RelativeDistinguishedName(it) }, false)

        /** Parse an RFC 2253 string (e.g., `CN=John Doe,O=Company,C=US`). */
        fun fromString(value: String): X500Name {
            if (value.isEmpty()) return X500Name(emptyList())

            val rdns = with(RelativeDistinguishedName) {
                value.splitRespectingEscapeAndQuotes(',', ';')
            }.map { rdn ->
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
