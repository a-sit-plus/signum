package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.encoding.parse
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.fromAsn1

/**
 * X.500 Name (used in X.509 Certificates)
 */
class RelativeDistinguishedName(
    val attrsAndValues: Set<AttributeTypeAndValue>,
    performValidation: Boolean = true,
) : WithSourceRepresentation {
    override val sourceRepresentation = SourceRepresentationStorage()

    constructor(singleItem: AttributeTypeAndValue) : this(setOf(singleItem))

    /**
     * Convenience: a single-attribute RDN from an awesn1 [X500AttributeTypeAndValue], e.g.
     * `RelativeDistinguishedName(X500AttributeTypeAndValue.CommonName("ACME"))`. Wraps it in the
     * generic bridge [AttributeTypeAndValue] so callers needn't depend on the typed attributes in
     * `indispensable-pkix`.
     */
    constructor(singleItem: X500AttributeTypeAndValue) : this(
        AttributeTypeAndValue.fromAsn1(singleItem))

    val isValid: Boolean by lazy {
        attrsAndValues.isStructurallyValid() &&
                attrsAndValues.all { it.isValid != false }
    }

    init {
        if (performValidation && !isValid) throw Asn1Exception("Invalid RelativeDistinguishedName!")
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RelativeDistinguishedName) return false
        return attrsAndValues == other.attrsAndValues
    }

    override fun hashCode(): Int = attrsAndValues.hashCode()

    override fun toString() = "RelativeDistinguishedName(attrsAndValues=${attrsAndValues.joinToString()})"

    companion object {

        /** Parse a single RDN string (e.g., "CN=John Doe+O=Company"). */
        fun fromString(rdnStr: String): RelativeDistinguishedName {
            val atvs = rdnStr.splitRespectingEscapeAndQuotes('+').map { atvStr ->
                val parts = atvStr.splitFirstUnescaped( '=')
                if (parts.size != 2) throw IllegalArgumentException("Invalid RDN part: $atvStr")
                AttributeTypeAndValue.fromString(parts[0], parts[1])
                    ?: throw IllegalArgumentException("Unknown RDN part: $atvStr")
            }
            return RelativeDistinguishedName(atvs.toSet())
        }

        //internal for tests
        internal fun String.splitFirstUnescaped(delimiter: Char): List<String> {
            val regex = Regex("(?<!\\\\)${Regex.escape(delimiter.toString())}")
            return this.split(regex, limit = 2)
        }

        //internal for tests
        internal fun String.splitRespectingEscapeAndQuotes(vararg delimiters: Char): List<String> {
            val parts = mutableListOf<String>()
            val sb = StringBuilder()
            var escaped = false
            var inQuotes = false

            this.forEach { c ->
                when {
                    escaped -> {
                        sb.append('\\').append(c)
                        escaped = false
                    }

                    c == '\\' -> escaped = true
                    c == '"' -> {
                        sb.append(c)
                        inQuotes = !inQuotes
                    }

                    c in delimiters && !inQuotes -> {
                        parts.add(sb.toString())
                        sb.clear()
                    }

                    else -> sb.append(c)
                }
            }

            if (escaped) sb.append('\\')
            parts.add(sb.toString())
            return parts
        }
    }
}

private fun Set<AttributeTypeAndValue>.isStructurallyValid(): Boolean =
    isNotEmpty() && allDistinctByOids()

// TODO: this should be subclassable by registrations and stuff
open class AttributeTypeAndValue protected constructor(
    override val oid: ObjectIdentifier,
    /** Raw X.509 attribute value; fails if the attribute has no X.509 representation. */
    // TODO: this assumes X.509 basis, still (a comment inline says this is backed by the RFC?)
    // if this is not true, we should have a shared base interface for value and go from there
    val value: Asn1Element
) : Identifiable, WithSourceRepresentation {
    override val sourceRepresentation = SourceRepresentationStorage()

    override fun toString() = "AttributeTypeAndValue(${toRfc2253String()})"

    // TODO: this is where we need to replace attribute lookup
    val typeString: String get() = Signum.attributeNameFor(oid) ?: oid.toString()
    protected val valueAsn1String by lazy { catchingUnwrapped { Asn1String.decodeFromTlv(value.asPrimitive()) } }

    /**
     * Validates recognized ASN.1 strings. For opaque non-string values, `null` means that no
     * validator is available; an unknown attribute's syntax need not be a string.
     */
    open val isValid: Boolean? get() =
        if (value.tag in Asn1String.leadingTags) valueAsn1String.mapCatching { it.isValid }.getOrElse { false }
        else null

    val valueString get() =
        valueAsn1String.mapCatching {
            canonicalizeRfc2253String(it.value)
        }.getOrElse { "#" + value.derEncoded.toHexString() }

    /**
     * Converts the current AttributeTypeAndValue instance into a string representation
     * that conforms to the RFC 2253 standard for Distinguished Names (DNs).
     *
     * @return A string representation of the attribute's type and value in RFC 2253 format.
     * @throws Asn1Exception if the attribute has no X.509 representation,
     * as the RFC only defines string canonicalization for X.509
     */
    fun toRfc2253String(): String {
        // RFC 2253 canonical form for case-insensitive matching: fold the value to lower case too
        return "${typeString.lowercase() }=${valueString.lowercase()}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttributeTypeAndValue) return false
        return oid == other.oid && value == other.value
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }

    interface Descriptor<out T : AttributeTypeAndValue> : Identifiable {
        val canonicalName: String

        object OID {
            val commonName = ObjectIdentifier("2.5.4.3")
            val countryName = ObjectIdentifier("2.5.4.6")
            val localityName = ObjectIdentifier("2.5.4.7")
            val stateOrProvinceName = ObjectIdentifier("2.5.4.8")
            val streetAddress = ObjectIdentifier("2.5.4.9")
            val organizationName = ObjectIdentifier("2.5.4.10")
            val organizationalUnitName = ObjectIdentifier("2.5.4.11")
            val title = ObjectIdentifier("2.5.4.12")
            val telephoneNumber = ObjectIdentifier("2.5.4.20")
            val surname = ObjectIdentifier("2.5.4.4")
            val serialNumber = ObjectIdentifier("2.5.4.5")
            val name = ObjectIdentifier("2.5.4.41")
            val givenName = ObjectIdentifier("2.5.4.42")
            val initials = ObjectIdentifier("2.5.4.43")
            val generationQualifier = ObjectIdentifier("2.5.4.44")
            val dnQualifier = ObjectIdentifier("2.5.4.46")
            val domainComponent = ObjectIdentifier("0.9.2342.19200300.100.1.25")
            val userId = ObjectIdentifier("0.9.2342.19200300.100.1.1")
            val emailAddress = ObjectIdentifier("1.2.840.113549.1.9.1")
        }

        fun fromString(value: String): T
        fun fromValue(value: Asn1Element): T

    }


    companion object {

        operator fun invoke(oid: ObjectIdentifier, value: Asn1Element): AttributeTypeAndValue =
            // TODO: attribute descriptor by oid lookup
            Signum.attributeDescriptorFor(oid)?.fromValue(value) ?: AttributeTypeAndValue(oid, value)

        fun fromString(type: String, value: String): AttributeTypeAndValue? {
            val key = type.trim()
            val v = value.trim()
            // RFC 4514 §2.4 hexstring form: the value is its DER encoding in hex (e.g. "#130138").
            if (v.length > 1 && v.first() == '#' &&  isHexString(v.substring(1))) {
                catchingUnwrapped { Asn1Element.parse(v.substring(1).hexToByteArray()) }.getOrNull()?.let { element ->
                    // TODO: attribute descriptor by name lookup
                    val oid = Signum.attributeDescriptorForName(key)?.oid
                        ?: catchingUnwrapped { ObjectIdentifier(key) }.getOrNull() ?: return null
                    return invoke(oid, element)
                }
            }
            // Otherwise unquote/unescape to the raw value; the typed Asn1String holds the raw content,
            // and toRfc2253String re-escapes on output (RFC 4514). This keeps the stored value correct
            // (no escape backslashes in the DER) and works for PrintableString/IA5 attributes too.
            val raw = unescapeRfc2253(v)
            Signum.attributeDescriptorForName(key)?.let { return it.fromString(raw) }
            // Fall back to a raw dotted-OID attribute type (e.g. "1.2.3.4.5"); value carried as a UTF8String.
            val oid = catchingUnwrapped { ObjectIdentifier(key) }.getOrNull() ?: return null
            return invoke(oid, Asn1String.UTF8(raw).encodeToTlv())
        }
    }
}

private class StandardX500AttributeDescriptor(
    override val oid: ObjectIdentifier,
    override val canonicalName: String,
    private val stringFactory: (String) -> Asn1String,
) : AttributeTypeAndValue.Descriptor<AttributeTypeAndValue> {
    override fun fromString(value: String): AttributeTypeAndValue =
        ATV(oid, stringFactory(value).encodeToTlv())

    override fun fromValue(value: Asn1Element): AttributeTypeAndValue = ATV(oid, value)

    private class ATV(oid: ObjectIdentifier, value: Asn1Element) : AttributeTypeAndValue(oid, value) {
        // Standard X.500 attributes require a string; an opaque value here is invalid.
        override val isValid get() = valueAsn1String.mapCatching { it.isValid }.getOrElse { false }
    }
}

internal val standardX500AttributeDescriptors: List<AttributeTypeAndValue.Descriptor<*>> = listOf(
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.commonName, "CN", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.countryName, "C", Asn1String::Printable),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.localityName, "L", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.stateOrProvinceName, "ST", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.streetAddress, "STREET", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.organizationName, "O", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.organizationalUnitName, "OU", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.title, "T", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.telephoneNumber, "TELEPHONENUMBER", Asn1String::Printable),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.surname, "SURNAME", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.serialNumber, "SERIALNUMBER", Asn1String::Printable),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.name, "NAME", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.givenName, "GIVENNAME", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.initials, "INITIALS", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.generationQualifier, "GENERATION", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.dnQualifier, "DNQUALIFIER", Asn1String::Printable),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.domainComponent, "DC", Asn1String::IA5),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.userId, "UID", Asn1String::UTF8),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.emailAddress, "EMAILADDRESS", Asn1String::IA5),
)

internal val standardX500AttributeAliases = mapOf(
    "COMMONNAME" to AttributeTypeAndValue.Descriptor.OID.commonName,
    "COUNTRY" to AttributeTypeAndValue.Descriptor.OID.countryName,
    "COUNTRYNAME" to AttributeTypeAndValue.Descriptor.OID.countryName,
    "LOCALITY" to AttributeTypeAndValue.Descriptor.OID.localityName,
    "LOCALITYNAME" to AttributeTypeAndValue.Descriptor.OID.localityName,
    "S" to AttributeTypeAndValue.Descriptor.OID.stateOrProvinceName,
    "STATEORPROVINCENAME" to AttributeTypeAndValue.Descriptor.OID.stateOrProvinceName,
    "STREETADDRESS" to AttributeTypeAndValue.Descriptor.OID.streetAddress,
    "ORGANIZATION" to AttributeTypeAndValue.Descriptor.OID.organizationName,
    "ORGANIZATIONNAME" to AttributeTypeAndValue.Descriptor.OID.organizationName,
    "ORGANIZATIONALUNIT" to AttributeTypeAndValue.Descriptor.OID.organizationalUnitName,
    "ORGANIZATIONALUNITNAME" to AttributeTypeAndValue.Descriptor.OID.organizationalUnitName,
    "TITLE" to AttributeTypeAndValue.Descriptor.OID.title,
    "DNQ" to AttributeTypeAndValue.Descriptor.OID.dnQualifier,
    "EMAIL" to AttributeTypeAndValue.Descriptor.OID.emailAddress,
)

private fun isHexString(s: String): Boolean =
    s.isNotEmpty() && s.length % 2 == 0 && s.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }

/** Unquote (legacy RFC 1779) and unescape an RFC 2253/4514 attribute value string into its raw text. */
private fun unescapeRfc2253(value: String): String {
    var s = value
    if (s.length >= 2 && s.first() == '"' && s.last() == '"') s = s.substring(1, s.length - 1)
    val sb = StringBuilder()
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c != '\\') { sb.append(c); i++; continue }
        if (i + 1 >= s.length) break // dangling trailing backslash: drop
        sb.append(s[i + 1]); i += 2
    }
    return sb.toString().trim()
}

/**
 * Escapes a raw attribute value into RFC 4514 string form: the special characters `, + " \ < > ; =`
 * and a leading `#` are backslash-escaped, and runs of whitespace collapse to a single space.
 * Leading/trailing whitespace is assumed already trimmed (see [unescapeRfc2253]).
 */
private fun canonicalizeRfc2253String(input: String): String {
    if (input.isEmpty()) return ""
    val escapees = ",+<>;\"\\="
    return buildString {
        if (input.first() == '#') append('\\') // escape a literal leading '#' (hexstring '#' is decoded at parse)
        var previousWasSpace = false
        input.forEach { c ->
            when {
                c.isWhitespace() -> if (!previousWasSpace) { append(' '); previousWasSpace = true }
                c in escapees -> { append('\\').append(c); previousWasSpace = false }
                else -> { append(c); previousWasSpace = false }
            }
        }
    }.trim()
}
