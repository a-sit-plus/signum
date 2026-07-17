package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer

/**
 * The DER/X.509 specialization of [Name] (an X.500 directory name) — a certificate issuer/subject.
 * RFC 2253 parsing/printing and the awesn1 backing live here; the encoding-agnostic abstraction is
 * [Name].
 *
 * This is a pure [Name.X509Representable]. Using an [X500Name] as a
 * `GeneralName`.
 */
class X500Name constructor(
    override val relativeDistinguishedNames: List<RelativeDistinguishedName>,
    performValidation: Boolean,
) : Name.X509Representable {

    override val asn1Representation: List<X500RelativeDistinguishedName>
        get() = relativeDistinguishedNames.map { it.asn1Representation }

    val isValid: Boolean by lazy {
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

    /**
     * Convenience: a single-RDN, single-attribute name from an awesn1 [X500AttributeTypeAndValue],
     * e.g. `X500Name(X500AttributeTypeAndValue.CommonName("ACME"))`.
     */
    @Throws(Asn1Exception::class)
    constructor(singleAttribute: X500AttributeTypeAndValue) : this(RelativeDistinguishedName(singleAttribute))

    companion object : DerDecodable<List<X500RelativeDistinguishedName>, X500Name> {
        /** The RDNSequence serializer (`SEQUENCE OF RelativeDistinguishedName`). */
        val serializer: KSerializer<List<X500RelativeDistinguishedName>> =
            ListSerializer(X500RelativeDistinguishedName.serializer())

        override fun decodeFromTlv(
            serializer: KSerializer<List<X500RelativeDistinguishedName>>,
            src: Asn1Element,
            der: Der,
        ): X500Name = X500Name(der.decodeFromTlv(serializer, src).map { RelativeDistinguishedName(it) }, false)

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

            val lastRdn = value.substring(start).trim()
            if (lastRdn.isNotEmpty()) rdns.add(RelativeDistinguishedName.fromString(lastRdn))

            return X500Name(rdns)
        }
    }

    override fun toString() = "X500Name(RDNs=${relativeDistinguishedNames.joinToString()})"

    fun toRfc2253String(): String {
        // RDN order is preserved; ATVs within a (multi-valued) RDN are sorted by attribute OID
        // (DER encoding order, unsigned) for a canonical form.
        return relativeDistinguishedNames.joinToString(",") { rdn ->
            rdn.attrsAndValues
                .sortedBy { it.oid }
                .joinToString("+") { atv -> atv.toRfc2253String().trim() }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X500Name

        if (isValid != other.isValid) return false
        if (relativeDistinguishedNames != other.relativeDistinguishedNames) return false

        return true
    }

    override fun hashCode(): Int {
        var result = isValid.hashCode()
        result = 31 * result + relativeDistinguishedNames.hashCode()
        return result
    }
}

/**
 * Returns the most specific (i.e. last-listed) CommonName attribute of this [Name], or `null`
 * if none is present. Used for RFC 5280 §4.2.1.10 name-constraint fallback handling.
 */
fun Name.findMostSpecificCommonName(): AttributeTypeAndValue.X509Representable? =
    relativeDistinguishedNames.asReversed().firstNotNullOfOrNull { rdn ->
        rdn.attrsAndValues.firstOrNull { it.oid == X500AttributeTypeAndValue.COMMON_NAME_OID } as? AttributeTypeAndValue.X509Representable
    }
