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

    companion object : Asn1Decodable<Asn1Set, RelativeDistinguishedName> {
        override fun doDecode(src: Asn1Set): RelativeDistinguishedName = src.decodeRethrowing {
            buildList {
                while (hasNext()) {
                    val child = next().asSequence()
                    add(AttributeTypeAndValue.decodeFromTlv(child))
                }
            }.let(::RelativeDistinguishedName)
        }

        /**
         * Parse a single RDN string (e.g., "CN=John Doe+O=Company")
         */
        fun parseFromString(rdnStr: String): RelativeDistinguishedName {
            val atvStrings = splitRespectingEscape(rdnStr, '+')
            val atvs = atvStrings.map { atvStr ->
                val parts = splitFirstUnescaped(atvStr, '=')
                if (parts.size != 2) throw IllegalArgumentException("Invalid RDN part: $atvStr")
                AttributeTypeAndValue.parseFromString(parts[0], parts[1])
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
                        sb.append(c)
                        escaped = false
                    }
                    c == '\\' -> escaped = true
                    c == delimiter -> {
                        // split here
                        return listOf(sb.toString(), input.substring(i + 1))
                    }
                    else -> sb.append(c)
                }
            }
            return listOf(sb.toString()) // delimiter not found
        }


        /** Utility function that respects escape sequences */
        private fun splitRespectingEscape(input: String, delimiter: Char): List<String> {
            val parts = mutableListOf<String>()
            val sb = StringBuilder()
            var escaped = false
            input.forEach { c ->
                when {
                    escaped -> {
                        sb.append(c)
                        escaped = false
                    }
                    c == '\\' -> escaped = true
                    c == delimiter -> {
                        parts.add(sb.toString())
                        sb.clear()
                    }
                    else -> sb.append(c)
                }
            }
            parts.add(sb.toString())
            return parts
        }
    }

    override fun toString() = "DistinguishedName(attrsAndValues=${attrsAndValues.joinToString()})"

}

open class AttributeTypeAndValue(
    override val oid: ObjectIdentifier,
    val value: Asn1Element
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    override fun toString() = value.toString()

    class CommonName(value: Asn1Element) : AttributeTypeAndValue(OID, value) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.commonName
        }
    }

    class Country(value: Asn1Element) : AttributeTypeAndValue(OID, value) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.countryName
        }
    }

    class Organization(value: Asn1Element) : AttributeTypeAndValue(OID, value) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.organizationName
        }
    }

    class OrganizationalUnit(value: Asn1Element) : AttributeTypeAndValue(OID, value) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.organizationalUnitName
        }
    }

    class EmailAddress(value: Asn1Element) : AttributeTypeAndValue(OID, value) {
        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
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
        fun parseFromString(type: String, value: String): AttributeTypeAndValue {
            val asn1String = Asn1String.UTF8(value)
            return when (type.uppercase()) {
                "CN" -> CommonName(asn1String)
                "O" -> Organization(asn1String)
                "OU" -> OrganizationalUnit(asn1String)
                "C" -> Country(asn1String)
                "EMAILADDRESS" -> EmailAddress(asn1String)
                else -> AttributeTypeAndValue(ObjectIdentifier(type), asn1String.encodeToTlv())
            }
        }
    }

    fun toRFC2253String(): String {
        val type = oidToString()

        val valStr = (value as? Asn1Primitive)?.let { prim ->
            runCatching {
                canonicalizeString(Asn1String.decodeFromTlv(prim).value)
            }.getOrElse {
                "#" + prim.content.toHexString()
            }
        } ?: ("#" + value.toDerHexString())

        return "$type=$valStr".lowercase()
    }


    /**
     * Apply RFC 2253 escaping + whitespace rules.
     */
    private fun canonicalizeString(input: String): String {
        val escapees = ",+<>;\"\\="
        if (input.isEmpty()) return ""

        val sb = StringBuilder()
        var previousWasSpace = false

        input.forEachIndexed { i, c ->
            when {
                c.isWhitespace() -> {
                    if (i != 0 && !previousWasSpace) {
                        sb.append(' ')
                        previousWasSpace = true
                    } else if (i == 0) {
                        sb.append(c)
                        previousWasSpace = true
                    }
                }
                else -> {
                    if (c in escapees || (i == 0 && c == '#')) {
                        sb.append('\\')
                    }
                    sb.append(c)
                    previousWasSpace = false
                }
            }
        }

        return sb.toString().trim()
    }





    private fun oidToString(): String = when (oid) {
        CommonName.OID -> "CN"
        Organization.OID -> "O"
        OrganizationalUnit.OID -> "OU"
        Country.OID -> "C"
        EmailAddress.OID -> "EMAILADDRESS"
        else -> oid.toString()
    }

}