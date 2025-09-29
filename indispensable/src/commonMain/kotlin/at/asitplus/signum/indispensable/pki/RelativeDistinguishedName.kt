package at.asitplus.signum.indispensable.pki

import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1Set
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.asn1.runRethrowing

/**
 * X.500 Name (used in X.509 Certificates)
 */
data class RelativeDistinguishedName(val attrsAndValues: List<AttributeTypeAndValue>) : Asn1Encodable<Asn1Set> {

    constructor(singleItem: AttributeTypeAndValue) : this(listOf(singleItem))

    override fun encodeToTlv() = runRethrowing {
        Asn1.Set {
            attrsAndValues.forEach { +it }
        }
    }

    val sortedAttrsAndValues by lazy {
        if (attrsAndValues.size > 1) {
            attrsAndValues.sortedWith(compareBy { atv ->
                rfc2253Order[atv.attrType.uppercase()] ?: Int.MAX_VALUE
            })
        } else {
            attrsAndValues
        }
    }

    companion object : Asn1Decodable<Asn1Set, RelativeDistinguishedName> {
        override fun doDecode(src: Asn1Set): RelativeDistinguishedName = src.decodeRethrowing {
            buildList {
                while (hasNext()) {
                    val child = next().asSequence()
                    add(AttributeTypeAndValue.decodeFromTlv(child))
                }
            }.let(::RelativeDistinguishedName)
        }

        // Predefined RFC2253 keyword order
        private val rfc2253Order = listOf(
            "CN", "C", "L", "S", "ST", "O", "OU", "T", "IP", "STREET",
            "DC", "DNQUALIFIER", "DNQ", "SURNAME", "GIVENNAME",
            "INITIALS", "GENERATION", "EMAIL", "EMAILADDRESS",
            "UID", "SERIALNUMBER"
        ).withIndex().associate { it.value.uppercase() to it.index }

        /**
         * Parse a single RDN string (e.g., "CN=John Doe+O=Company")
         */
        fun fromString(rdnStr: String): RelativeDistinguishedName {
            val atvStrings = splitRespectingEscapeAndQuotes(rdnStr, '+')
            val atvs = atvStrings.map { atvStr ->
                val parts = splitFirstUnescaped(atvStr, '=')
                if (parts.size != 2) throw IllegalArgumentException("Invalid RDN part: $atvStr")
                AttributeTypeAndValue.fromString(parts[0], parts[1])
            }
            return RelativeDistinguishedName(atvs)
        }

        /** Split on the first unescaped delimiter */
        private fun splitFirstUnescaped(input: String, delimiter: Char): List<String> {
            val sb = StringBuilder()
            var escaped = false
            for ((i, c) in input.withIndex()) {
                when {
                    escaped -> {
                        sb.append('\\').append(c) // preserve the escape
                        escaped = false
                    }
                    c == '\\' -> escaped = true
                    c == delimiter -> return listOf(sb.toString(), input.substring(i + 1))
                    else -> sb.append(c)
                }
            }
            return listOf(sb.toString())
        }


        /** Utility function that respects escape sequences */
        private fun splitRespectingEscapeAndQuotes(input: String, delimiter: Char): List<String> {
            val parts = mutableListOf<String>()
            val sb = StringBuilder()
            var escaped = false
            var inQuotes = false

            input.forEach { c ->
                when {
                    escaped -> {
                        sb.append('\\').append(c) // preserve escape
                        escaped = false
                    }
                    c == '\\' -> escaped = true
                    c == '"' -> {
                        sb.append(c)
                        inQuotes = !inQuotes
                    }
                    c == delimiter && !inQuotes -> {
                        parts.add(sb.toString())
                        sb.clear()
                    }
                    else -> sb.append(c)
                }
            }

            parts.add(sb.toString().trim())
            return parts
        }


    }

    override fun toString() = "DistinguishedName(attrsAndValues=${attrsAndValues.joinToString()})"

}

open class AttributeTypeAndValue(
    override val oid: ObjectIdentifier,
    val value: Asn1Element,
    val attrType: String = oid.toString()
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    override fun toString() = value.toString()

    class CommonName(value: Asn1Element) : AttributeTypeAndValue(OID, value, TYPE) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            const val TYPE = "CN"
            val OID = KnownOIDs.commonName
        }
    }

    class Country(value: Asn1Element) : AttributeTypeAndValue(OID, value, TYPE) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            const val TYPE = "C"
            val OID = KnownOIDs.countryName
        }
    }

    class Organization(value: Asn1Element) : AttributeTypeAndValue(OID, value, TYPE) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            const val TYPE = "O"
            val OID = KnownOIDs.organizationName
        }
    }

    class OrganizationalUnit(value: Asn1Element) : AttributeTypeAndValue(OID, value, TYPE) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            const val TYPE = "OU"
            val OID = KnownOIDs.organizationalUnitName
        }
    }

    class EmailAddress(value: Asn1Element) : AttributeTypeAndValue(OID, value, TYPE) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            const val TYPE = "EMAILADDRESS"
            val OID = KnownOIDs.emailAddress_1_2_840_113549_1_9_1
        }
    }

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        +value
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AttributeTypeAndValue

        if (toRFC2253String() != other.toRFC2253String()) return false
        if (oid != other.oid) return false

        return true
    }

    override fun hashCode(): Int {
        var result = value.hashCode()
        result = 31 * result + oid.hashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, AttributeTypeAndValue> {

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): AttributeTypeAndValue = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()
            if (oid.nodes.size >= 3 && oid.toString().startsWith("2.5.4.")) {
                val asn1String = next().asPrimitive()
                val str = catching { Asn1String.decodeFromTlv(asn1String) }
                return@decodeRethrowing when (oid) {
                    CommonName.OID -> str.fold(onSuccess = { CommonName(it) }, onFailure = { CommonName(asn1String) })
                    Country.OID -> str.fold(onSuccess = { Country(it) }, onFailure = { Country(asn1String) })
                    EmailAddress.OID -> str.fold(onSuccess = { EmailAddress(it) }, onFailure = { EmailAddress(asn1String) })
                    Organization.OID -> str.fold(
                        onSuccess = { Organization(it) },
                        onFailure = { Organization(asn1String) })

                    OrganizationalUnit.OID -> str.fold(
                        onSuccess = { OrganizationalUnit(it) },
                        onFailure = { OrganizationalUnit(asn1String) })

                    else -> AttributeTypeAndValue(oid, asn1String)
                }
            }
            AttributeTypeAndValue(oid, next())
        }

        /**
         * Parse an individual type=value string into the correct AttributeTypeAndValue subclass
         */
        fun fromString(type: String, value: String): AttributeTypeAndValue {
            val trimmed = value.trim()
            val asn1String = Asn1String.UTF8(trimmed)
            return when (type.uppercase()) {
                "CN" -> CommonName(asn1String)
                "O" -> Organization(asn1String)
                "OU" -> OrganizationalUnit(asn1String)
                "C" -> Country(asn1String)
                "EMAILADDRESS" -> EmailAddress(asn1String)
                else -> AttributeTypeAndValue(ObjectIdentifier("0.0"), asn1String.encodeToTlv(), type)
            }
        }
    }

    fun toRFC2253String(): String {
        val attrValue = (value as? Asn1Primitive)?.let { prim ->
            runCatching {
                var decodedValue = Asn1String.decodeFromTlv(prim).value
                val wasQuoted = decodedValue.startsWith("\"") && decodedValue.endsWith("\"")
                decodedValue = decodedValue.removeSurrounding("\"")
                val wasBackslashFirst = decodedValue.startsWith("\\")
                val unescaped = decodedValue.replace("""\\(.)""".toRegex(), "$1")

                canonicalizeString(unescaped, wasQuoted, wasBackslashFirst)
            }.getOrElse { "#" + prim.content.toHexString() }
        } ?: ("#" + value.toDerHexString())

        return "$attrType=$attrValue".lowercase()
    }



    /**
     * Canonicalize string according to RFC 2253 rules.
     *
     * @param wasQuoted If true, we preserve characters like '+' without escaping.
     * @param wasBackSlashFirst used for checking is '#' intentionally escaped in hex
     */
    private fun canonicalizeString(
        input: String,
        wasQuoted: Boolean,
        wasBackSlashFirst: Boolean
    ): String {
        if (input.isEmpty()) return ""
        if (wasQuoted) return input.trim()
        val escapees = ",+<>;\"\\="

        // Escape leading/trailing spaces (RFC 2253)
        val s = buildString {
            if (input.startsWith(' ')) append('\\')
            append(input)
            if (input.endsWith(' ')) {
                deleteAt(length - 1)
                append("\\ ")
            }
        }

        return buildString {
            var previousWasSpace = false
            var startIndex = 0

            // Handle leading # for hex encoding
            if (s.startsWith("#")) {
                val hexPart = s.drop(1)
                val isHex = hexPart.length % 2 == 0 && hexPart.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
                if (isHex && !wasBackSlashFirst) {
                    append('#')
                    startIndex = 1
                } else {
                    append('\\').append('#')
                    startIndex = 1
                }
            }

            for (c in s.drop(startIndex)) {
                when {
                    c.isWhitespace() -> {
                        if (!previousWasSpace) {
                            append(' ')
                            previousWasSpace = true
                        }
                    }
                    c in escapees -> {
                        append('\\').append(c)
                        previousWasSpace = false
                    }
                    else -> {
                        append(c)
                        previousWasSpace = false
                    }
                }
            }
        }
    }
}