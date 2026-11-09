@file:OptIn(at.asitplus.signum.SignumInternals::class)

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
import at.asitplus.signum.indispensable.toAsn1

/**
 * X.500 Name (used in X.509 Certificates)
 */
class RelativeDistinguishedName(
    val attrsAndValues: Set<AttributeTypeAndValue>,
    performValidation: Boolean = true,
) : WithSourceRepresentation {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()

    constructor(singleItem: AttributeTypeAndValue) : this(setOf(singleItem))

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
        /** Creates a single-attribute RDN from its ASN.1 representation. */
        operator fun invoke(singleItem: X500AttributeTypeAndValue): RelativeDistinguishedName =
            RelativeDistinguishedName(AttributeTypeAndValue.fromAsn1(singleItem))

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

/** An open attribute family. Only interpreted subtypes expose semantic values. */
interface AttributeTypeAndValue : Identifiable, WithSourceRepresentation {
    val isValid: Boolean? get() = null

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

    }


    companion object {

        operator fun invoke(oid: ObjectIdentifier, value: Asn1Element): AttributeTypeAndValue =
            fromAsn1(X500AttributeTypeAndValue(oid, value))

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

/** Text is semantic; its original ASN.1 string tag belongs to the retained representation. */
open class TextAttributeTypeAndValue(
    final override val oid: ObjectIdentifier,
    val text: String,
) : AttributeTypeAndValue {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val isValid: Boolean get() = when (oid) {
        AttributeTypeAndValue.Descriptor.OID.domainComponent,
        AttributeTypeAndValue.Descriptor.OID.emailAddress -> text.all { it.code < 128 }
        AttributeTypeAndValue.Descriptor.OID.countryName,
        AttributeTypeAndValue.Descriptor.OID.dnQualifier,
        AttributeTypeAndValue.Descriptor.OID.serialNumber,
        AttributeTypeAndValue.Descriptor.OID.telephoneNumber -> text.all {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it in " '()+,-./:=?"
        }
        else -> true
    }
    override fun equals(other: Any?): Boolean = other is TextAttributeTypeAndValue && oid == other.oid && text == other.text
    override fun hashCode(): Int = 31 * oid.hashCode() + text.hashCode()
    override fun toString(): String = "AttributeTypeAndValue(${toRfc2253String()})"
}

class OpaqueAttributeTypeAndValue(
    override val oid: ObjectIdentifier,
    val decodingFailure: at.asitplus.signum.UnsupportedCryptoException? = null,
    override val isValid: Boolean? = null,
) : AttributeTypeAndValue {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    @OptIn(SignumInternals::class)
    override fun equals(other: Any?): Boolean = this === other || other is OpaqueAttributeTypeAndValue &&
            oid == other.oid && (sourceRepresentation presentAndEquals other.sourceRepresentation)
    override fun hashCode(): Int = 31 * oid.hashCode() + sourceRepresentation.hashCode()
    override fun toString(): String = "OpaqueAttributeTypeAndValue($oid, $sourceRepresentation)"
}

val AttributeTypeAndValue.typeString: String get() = Signum.attributeNameFor(oid) ?: oid.toString()
val AttributeTypeAndValue.valueString: String get() = when (this) {
    is TextAttributeTypeAndValue -> canonicalizeRfc2253String(text)
    else -> toAsn1().value.let { value ->
        catchingUnwrapped { canonicalizeRfc2253String(Asn1String.decodeFromTlv(value.asPrimitive()).value) }
            .getOrElse { "#" + value.derEncoded.toHexString() }
    }
}
fun AttributeTypeAndValue.toRfc2253String(): String = "${typeString.lowercase()}=${valueString.lowercase()}"

private class StandardX500AttributeDescriptor(
    override val oid: ObjectIdentifier,
    override val canonicalName: String,
) : AttributeTypeAndValue.Descriptor<TextAttributeTypeAndValue> {
    override fun fromString(value: String) = TextAttributeTypeAndValue(oid, value)
}

internal val standardX500AttributeDescriptors: List<AttributeTypeAndValue.Descriptor<*>> = listOf(
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.commonName, "CN"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.countryName, "C"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.localityName, "L"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.stateOrProvinceName, "ST"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.streetAddress, "STREET"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.organizationName, "O"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.organizationalUnitName, "OU"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.title, "T"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.telephoneNumber, "TELEPHONENUMBER"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.surname, "SURNAME"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.serialNumber, "SERIALNUMBER"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.name, "NAME"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.givenName, "GIVENNAME"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.initials, "INITIALS"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.generationQualifier, "GENERATION"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.dnQualifier, "DNQUALIFIER"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.domainComponent, "DC"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.userId, "UID"),
    StandardX500AttributeDescriptor(AttributeTypeAndValue.Descriptor.OID.emailAddress, "EMAILADDRESS"),
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
