package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.installIndispensable
import at.asitplus.signum.internals.hexToByteArray
import kotlin.jvm.JvmSynthetic

/**
 * X.500 Name (used in X.509 Certificates)
 */
class RelativeDistinguishedName(
    val attrsAndValues: Set<AttributeTypeAndValue>,
    performValidation: Boolean = true,
) : WithSourceRepresentation {
    override val sourceRepresentation = SourceRepresentationStorage()

    constructor(singleItem: AttributeTypeAndValue) : this(setOf(singleItem))

    internal fun hasValidStructure(): Boolean = attrsAndValues.isStructurallyValid()

    init {
        if (performValidation && !hasValidStructure()) throw Asn1Exception("Invalid RelativeDistinguishedName structure!")
    }

    /**
     * Compares text attributes using Unicode default full case folding.
     * Turkic case folding (T mappings) is excluded.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RelativeDistinguishedName) return false
        return attributeCounts() == other.attributeCounts()
    }

    /**
     * Hashes text attributes using the same Unicode default full case folding as [equals].
     * Turkic case folding (T mappings) is excluded.
     */
    override fun hashCode(): Int = attributeCounts().hashCode()

    private fun attributeCounts() = attrsAndValues.groupingBy {
        if (it is TextAttributeTypeAndValue) it.oid to it.text.caseFold() else it
    }.eachCount()

    override fun toString() = "RelativeDistinguishedName(attrsAndValues=${attrsAndValues.joinToString()})"

    companion object {
        /** Creates a single-attribute RDN from its ASN.1 representation. */
        operator fun invoke(singleItem: X500AttributeTypeAndValue): RelativeDistinguishedName =
            RelativeDistinguishedName(AttributeTypeAndValue.fromAsn1(singleItem))

        /** Parse a single RDN string (e.g., "CN=John Doe+O=Company"). */
        fun fromString(rdnStr: String): RelativeDistinguishedName {
            val atvs = rdnStr.splitRespectingEscapeAndQuotes('+').map(AttributeTypeAndValue::fromString)
            return RelativeDistinguishedName(atvs.toSet())
        }

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

private fun String.caseFold(): String = buildString(length) {
    val text = this@caseFold
    var index = 0
    while (index < text.length) {
        val start = index
        val first = text[index++]
        //UTF-16, UTF-8 code point conversion. Sting.codePintAt is JVM-only!
        val codePoint = if (first.isHighSurrogate() && index < text.length && text[index].isLowSurrogate()) {
            0x10000 + ((first.code - 0xD800) shl 10) + (text[index++].code - 0xDC00)
        } else {
            first.code
        }
        val replacement = CaseFoldingMap[codePoint]
        if (replacement != null) append(replacement) else append(text, start, index)
    }
}

/** An open attribute family. Only interpreted subtypes expose semantic values. */
interface AttributeTypeAndValue : Identifiable, WithSourceRepresentation {
    @SignumInternals
    class Unknown private constructor(
        source: X500AttributeTypeAndValue,
        lookupResult: UnsupportedCryptoException,
    ) : AttributeTypeAndValue, ServiceLoader.UnknownShim(source, lookupResult) {
        override val oid = source.oid

        companion object {
            @JvmSynthetic
            internal fun fromSource(source: X500AttributeTypeAndValue, lookupResult: UnsupportedCryptoException) =
                Unknown(source, lookupResult)
        }
    }

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

    companion object {
        init { Signum.installIndispensable() }

        private fun String.splitFirstUnescaped(delimiter: Char): List<String> {
            val regex = Regex("(?<!\\\\)${Regex.escape(delimiter.toString())}")
            return this.split(regex, limit = 2)
        }

        /** constructs an ATV from type-value string form (e.g., `CN=Alice`) */
        fun fromString(str: String) = catchingUnwrappedAs(a = ::UnsupportedCryptoException) {
            val parts = str.splitFirstUnescaped( '=')
            if (parts.size != 2) throw Asn1Exception("Invalid ATV string: $str")
            fromString(parts[0], parts[1])
        }.getOrThrow()

        /** constructs an ATV from a type-value pair */
        fun fromString(type: String, value: String): AttributeTypeAndValue = catchingUnwrappedAs(a = ::UnsupportedCryptoException) {
            // covered options:
            // oid=kotlinstring
            // oid=#hexstring
            // alias=kotlinstring
            // alias=#hexstring
            val key = type.trim()
            val oid =
                if (key.firstOrNull()?.isDigit() == true) {
                    // digit: dot-notation OID
                    AttributeTypeAndValueProvider.Key(ObjectIdentifier(key))
                } else {
                    // not digit: string alias
                    AttributeTypeAndValueProvider.Key(key.trim().uppercase())
                }

            val v = value.trim()
            // RFC 4514 §2.4 hexstring form: the value is its DER encoding in hex (e.g. "#130138").
            val resolvedValue =
                if (v.firstOrNull() == '#') {
                    require(v.length > 1)
                    require(v.length % 2 == 1)
                    AttributeTypeAndValueProvider.Value(v.hexToByteArray(startIndex = 1))
                } else {
                    AttributeTypeAndValueProvider.Value(unescapeRfc2253(v))
                }

            ServiceLoader.load<AttributeTypeAndValueProvider>().get(type) {
                decodeATV(oid, resolvedValue)
            }
        }.getOrThrow()
    }
}

/** Text is semantic; its original ASN.1 string tag belongs to the retained representation. */
open class TextAttributeTypeAndValue(
    final override val oid: ObjectIdentifier,
    val text: String,
) : AttributeTypeAndValue {
    override val sourceRepresentation = SourceRepresentationStorage()
    override fun equals(other: Any?): Boolean = other is TextAttributeTypeAndValue && oid == other.oid && text == other.text
    override fun hashCode(): Int = 31 * oid.hashCode() + text.hashCode()
    override fun toString(): String = "AttributeTypeAndValue(${toRfc2253String()})"
}

fun AttributeTypeAndValue.toRfc2253String(): String {
    // Look up by OID so text providers can also re-emit opaque attributes.
    val (keyString, valueString) = ServiceLoader.load<AttributeTypeAndValueProvider>()
        .get(oid) { encodeATV(this@toRfc2253String) }
    return buildString {
        // append key
        when (keyString) {
            is AttributeTypeAndValueProvider.OID -> append(keyString.oid.toString())
            is AttributeTypeAndValueProvider.StringAlias -> append(keyString.str.uppercase())
        }
        // append delimiter
        append('=')
        // append value
        when (valueString) {
            is AttributeTypeAndValueProvider.StringValue -> append(canonicalizeRfc2253String(valueString.str))
            is AttributeTypeAndValueProvider.ByteArrayValue -> {
                append('#')
                append(valueString.bytes.toHexString())
            }
        }
    }
}

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
