package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Awesn1Backed
import at.asitplus.signum.indispensable.asn1.Awesn1BackedSerializer
import kotlin.text.toHexString

/**
 * X.500 Name (used in X.509 Certificates)
 */
class RelativeDistinguishedName(
    override val backing: X500RelativeDistinguishedName,
    performValidation: Boolean
) : Awesn1Backed<X500RelativeDistinguishedName> {

    val isValid: Boolean by lazy {
        backing.attrsAndValues.map { AttributeTypeAndValue(it) }.all { it.isValid == true }
    }

    init {
        if (performValidation && !isValid) throw Asn1Exception("Invalid RelativeDistinguishedName!")
    }

    constructor(attrsAndValues: List<AttributeTypeAndValue>) : this(
        X500RelativeDistinguishedName(attrsAndValues.map { it.backing }.toSet()),
        true
    )

    constructor(singleItem: AttributeTypeAndValue) : this(listOf(singleItem))


    companion object : Awesn1BackedSerializer<X500RelativeDistinguishedName, RelativeDistinguishedName>(
        X500RelativeDistinguishedName.serializer(), {
            RelativeDistinguishedName(it,false)
        }){

        /**
         * Parse a single RDN string (e.g., "CN=John Doe+O=Company")
         */
        fun fromString(rdnStr: String): RelativeDistinguishedName {
            val atvStrings = splitRespectingEscapeAndQuotes(rdnStr, '+')
            val atvs = atvStrings.map { atvStr ->
                val parts = splitFirstUnescaped(atvStr, '=')
                if (parts.size != 2) throw IllegalArgumentException("Invalid RDN part: $atvStr")
                AttributeTypeAndValue.fromString(parts[0], parts[1])?:throw  IllegalArgumentException("Unknown RDN part: $atvStr")
            }
            return RelativeDistinguishedName(atvs)
        }

        /** Split on the first unescaped delimiter */
        internal fun splitFirstUnescaped(input: String, delimiter: Char): List<String> {
            val regex = Regex("(?<!\\\\)${Regex.escape(delimiter.toString())}")
            return input.split(regex, limit = 2)
        }

        /** Utility function that respects escape sequences */
        internal fun splitRespectingEscapeAndQuotes(input: String, delimiter: Char): List<String> {
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

            parts.add(sb.toString())
            return parts
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RelativeDistinguishedName) return false

        if (backing != other.backing) return false

        return true
    }

    override fun hashCode(): Int {
        return backing.hashCode()
    }

    override fun toString(): String {
        return "RelativeDistinguishedName(" +
                "backing=$backing, " +
                "isValid=$isValid" +
                ")"
    }
}
open class AttributeTypeAndValue(
    override val backing: X500AttributeTypeAndValue
) : Identifiable, Awesn1Backed<X500AttributeTypeAndValue> {

    override val oid: ObjectIdentifier get() = backing.oid

    val displayName: String? get() = AttributeTypeOidMap.nameFor(oid)

    /**
     * Returns whether this string is valid:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented
     */
    val isValid: Boolean? by lazy {
        catchingUnwrapped { Asn1String.decodeFromTlv(backing.value.asPrimitive()).isValid }.getOrNull()
    }

    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(oid: ObjectIdentifier, value: Asn1String) : this(X500AttributeTypeAndValue(oid, value)) {
        if (isValid == false) {
            throw Asn1Exception(
                "Invalid AttributeTypeAndValue: $oid ${displayName?.let { "($it)" }} for value $value!"
            )
        }
    }

    class CommonName
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("CN")!!
        }
    }

    class Country
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("C")!!
        }
    }

    class Locality
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("L")!!
        }
    }

    class StateOrProvince
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("ST")!!
        }
    }

    class Organization
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("O")!!
        }
    }

    class OrganizationalUnit
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("OU")!!
        }
    }

    class Title
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("T")!!
        }
    }

    class Street
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("STREET")!!
        }
    }

    class DomainComponent
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("DC")!!
        }
    }

    class DistinguishedNameQualifier
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("DNQUALIFIER")!!
        }
    }

    class Surname
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("SURNAME")!!
        }
    }

    class GivenName
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("GIVENNAME")!!
        }
    }

    class Initials
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("INITIALS")!!
        }
    }

    class Generation
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("GENERATION")!!
        }
    }

    class EmailAddress
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("EMAILADDRESS")!!
        }
    }

    class UserId
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("UID")!!
        }
    }

    class SerialNumber
    /**
     * @throws Asn1Exception if an illegal value is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        val value: Asn1String,
    ) : AttributeTypeAndValue(OID, value) {

        @Throws(Asn1Exception::class)
        constructor(str: String) : this(Asn1String.UTF8(str))

        companion object {
            val OID = AttributeTypeOidMap.oidFor("SERIALNUMBER")!!
        }
    }

    companion object {

        /**
         * Parse an individual type=value string into the correct AttributeTypeAndValue subclass.
         *
         * @return null if none fits
         */
        fun fromString(type: String, value: String): AttributeTypeAndValue? {
            val trimmed = value.trim()
            val asn1String = Asn1String.UTF8(trimmed)

            return when (type.uppercase()) {
                "CN" -> CommonName(asn1String)
                "C" -> Country(asn1String)
                "L" -> Locality(asn1String)
                "S", "ST" -> StateOrProvince(asn1String)
                "O" -> Organization(asn1String)
                "OU" -> OrganizationalUnit(asn1String)
                "T" -> Title(asn1String)
                "STREET" -> Street(asn1String)
                "DC" -> DomainComponent(asn1String)
                "DNQ", "DNQUALIFIER" -> DistinguishedNameQualifier(asn1String)
                "SURNAME" -> Surname(asn1String)
                "GIVENNAME" -> GivenName(asn1String)
                "INITIALS" -> Initials(asn1String)
                "GENERATION" -> Generation(asn1String)
                "EMAIL", "EMAILADDRESS" -> EmailAddress(asn1String)
                "UID" -> UserId(asn1String)
                "SERIALNUMBER" -> SerialNumber(asn1String)
                else -> null
            }
        }

        /**
         * Wrap an already-decoded X500AttributeTypeAndValue in the matching subclass.
         */
        fun fromBacking(backing: X500AttributeTypeAndValue): AttributeTypeAndValue {
            val stringValue = runCatching {
                Asn1String.decodeFromTlv(backing.value.asPrimitive())
            }.getOrNull()

            return when {
                stringValue == null -> AttributeTypeAndValue(backing)
                backing.oid == CommonName.OID -> CommonName(stringValue)
                backing.oid == Country.OID -> Country(stringValue)
                backing.oid == Locality.OID -> Locality(stringValue)
                backing.oid == StateOrProvince.OID -> StateOrProvince(stringValue)
                backing.oid == Organization.OID -> Organization(stringValue)
                backing.oid == OrganizationalUnit.OID -> OrganizationalUnit(stringValue)
                backing.oid == Title.OID -> Title(stringValue)
                backing.oid == Street.OID -> Street(stringValue)
                backing.oid == DomainComponent.OID -> DomainComponent(stringValue)
                backing.oid == DistinguishedNameQualifier.OID -> DistinguishedNameQualifier(stringValue)
                backing.oid == Surname.OID -> Surname(stringValue)
                backing.oid == GivenName.OID -> GivenName(stringValue)
                backing.oid == Initials.OID -> Initials(stringValue)
                backing.oid == Generation.OID -> Generation(stringValue)
                backing.oid == EmailAddress.OID -> EmailAddress(stringValue)
                backing.oid == UserId.OID -> UserId(stringValue)
                backing.oid == SerialNumber.OID -> SerialNumber(stringValue)
                else -> AttributeTypeAndValue(backing)
            }
        }
    }

    fun toRfc2253String(): String {
        val attrValue = (backing.value as? Asn1Primitive)?.let { prim ->
            runCatching {
                var decodedValue = Asn1String.decodeFromTlv(prim).value
                val wasQuoted = decodedValue.startsWith("\"") && decodedValue.endsWith("\"")
                decodedValue = decodedValue.removeSurrounding("\"")
                val wasBackslashFirst = decodedValue.startsWith("\\")
                val unescaped = decodedValue.replace("""\\(.)""".toRegex(), "$1")

                canonicalizeString(unescaped, wasQuoted, wasBackslashFirst)
            }.getOrElse { "#" + prim.content.toHexString() }
        } ?: ("#" + backing.value.toDerHexString())

        return "${AttributeTypeOidMap.nameFor(oid) ?: oid}=$attrValue".lowercase()
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
        if (wasQuoted) return input.trim().replace(Regex("\\s+"), " ")
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

    override fun toString(): String {
        return "AttributeTypeAndValue(" +
                "backing=$backing" +
                ")"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttributeTypeAndValue) return false

        if (backing != other.backing) return false

        return true
    }

    override fun hashCode(): Int {
        return backing.hashCode()
    }
}


object AttributeTypeOidMap {
    private val nameToOid: Map<String, ObjectIdentifier> = mapOf(
        "CN" to ObjectIdentifier("2.5.4.3"),
        "C" to ObjectIdentifier("2.5.4.6"),
        "L" to ObjectIdentifier("2.5.4.7"),
        "ST" to ObjectIdentifier("2.5.4.8"),
        "O" to ObjectIdentifier("2.5.4.10"),
        "OU" to ObjectIdentifier("2.5.4.11"),
        "T" to ObjectIdentifier("2.5.4.12"),
        "STREET" to ObjectIdentifier("2.5.4.9"),
        "DC" to ObjectIdentifier("0.9.2342.19200300.100.1.25"),
        "DNQUALIFIER" to ObjectIdentifier("2.5.4.46"),
        "SURNAME" to ObjectIdentifier("2.5.4.4"),
        "GIVENNAME" to ObjectIdentifier("2.5.4.42"),
        "INITIALS" to ObjectIdentifier("2.5.4.43"),
        "GENERATION" to ObjectIdentifier("2.5.4.44"),
        "EMAILADDRESS" to ObjectIdentifier("1.2.840.113549.1.9.1"),
        "UID" to ObjectIdentifier("0.9.2342.19200300.100.1.1"),
        "SERIALNUMBER" to ObjectIdentifier("2.5.4.5"),
    )

    private val oidToName: Map<ObjectIdentifier, String> =
        nameToOid.entries.associate { (name, oid) -> oid to name }

    fun oidFor(name: String): ObjectIdentifier? =
        nameToOid[name.uppercase()]

    fun nameFor(oid: ObjectIdentifier): String? =
        oidToName[oid]

    val ORDER = listOf(
        "CN", "C", "L", "S", "ST", "O", "OU", "T", "IP", "STREET",
        "DC", "DNQUALIFIER", "DNQ", "SURNAME", "GIVENNAME",
        "INITIALS", "GENERATION", "EMAIL", "EMAILADDRESS",
        "UID", "SERIALNUMBER"
    ).withIndex().associate { it.value.uppercase() to it.index }
}
