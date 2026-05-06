package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.internals.orLazy
import kotlinx.serialization.KSerializer

/**
 * X.500 Name (used in X.509 Certificates)
 */
class RelativeDistinguishedName private constructor(
    providedAttrsAndValues: Set<AttributeTypeAndValue>?,
    providedAsn1Representation: X500RelativeDistinguishedName?,
    performValidation: Boolean,
) : DerEncodable<X500RelativeDistinguishedName> {

    constructor(attrsAndValues: Set<AttributeTypeAndValue>) : this(attrsAndValues, null, true)

    constructor(singleItem: AttributeTypeAndValue) : this(setOf(singleItem))

    internal constructor(
        asn1Representation: X500RelativeDistinguishedName,
        performValidation: Boolean = false,
    ) : this(null, asn1Representation, performValidation)

    override val asn1Representation: X500RelativeDistinguishedName by providedAsn1Representation orLazy {
        X500RelativeDistinguishedName(attrsAndValues.map { it.asn1Representation }.toSet())
    }

    val attrsAndValues: Set<AttributeTypeAndValue> by providedAttrsAndValues orLazy {
        asn1Representation.attrsAndValues.map(AttributeTypeAndValue::fromAsn1Representation).toSet()
    }

    val isValid: Boolean by lazy { attrsAndValues.all { it.isValid != false } }

    init {
        if (performValidation && !isValid) throw Asn1Exception("Invalid RelativeDistinguishedName!")
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RelativeDistinguishedName) return false
        return asn1Representation == other.asn1Representation
    }

    override fun hashCode(): Int = asn1Representation.hashCode()

    override fun toString() = "RelativeDistinguishedName(attrsAndValues=${attrsAndValues.joinToString()})"

    companion object : DerDecodable<X500RelativeDistinguishedName, RelativeDistinguishedName> {

        fun fromTlv(src: Asn1Element): RelativeDistinguishedName =
            decodeFromTlv(X500RelativeDistinguishedName.serializer(), src, DER)

        override fun decodeFromTlv(
            serializer: KSerializer<X500RelativeDistinguishedName>,
            src: Asn1Element,
            der: Der,
        ): RelativeDistinguishedName =
            RelativeDistinguishedName(der.decodeFromTlv(serializer, src), performValidation = false)

        /**
         * Parse a single RDN string (e.g., "CN=John Doe+O=Company").
         */
        fun fromString(rdnStr: String): RelativeDistinguishedName {
            val atvs = splitRespectingEscapeAndQuotes(rdnStr, '+').map { atvStr ->
                val parts = splitFirstUnescaped(atvStr, '=')
                if (parts.size != 2) throw IllegalArgumentException("Invalid RDN part: $atvStr")
                AttributeTypeAndValue.fromString(parts[0], parts[1])
                    ?: throw IllegalArgumentException("Unknown RDN part: $atvStr")
            }
            return RelativeDistinguishedName(atvs.toSet())
        }

        internal fun splitFirstUnescaped(input: String, delimiter: Char): List<String> {
            val regex = Regex("(?<!\\\\)${Regex.escape(delimiter.toString())}")
            return input.split(regex, limit = 2)
        }

        internal fun splitRespectingEscapeAndQuotes(input: String, delimiter: Char): List<String> {
            val parts = mutableListOf<String>()
            val sb = StringBuilder()
            var escaped = false
            var inQuotes = false

            input.forEach { c ->
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

                    c == delimiter && !inQuotes -> {
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

open class AttributeTypeAndValue private constructor(
    providedAsn1Representation: X500AttributeTypeAndValue?,
    providedContent: Pair<ObjectIdentifier, Asn1Element>?,
    validateValue: Boolean,
) : Identifiable, DerEncodable<X500AttributeTypeAndValue> {

    constructor(oid: ObjectIdentifier, value: Asn1Element) : this(null, oid to value, false)

    @Throws(Asn1Exception::class)
    constructor(oid: ObjectIdentifier, value: Asn1String) : this(null, oid to value.encodeToTlv(), true)

    internal constructor(asn1Representation: X500AttributeTypeAndValue) : this(asn1Representation, null, false)

    override val asn1Representation: X500AttributeTypeAndValue by providedAsn1Representation orLazy {
        val (oid, value) = requireNotNull(providedContent)
        X500AttributeTypeAndValue(oid, value)
    }

    override val oid: ObjectIdentifier by providedContent?.first orLazy {
        asn1Representation.oid
    }

    val value: Asn1Element by providedContent?.second orLazy {
        asn1Representation.value
    }

    val displayName: String? get() = AttributeTypeOidMap.nameFor(oid)

    /**
     * `true`: validation succeeded, `false`: validation failed, `null`: no validation implemented.
     */
    val isValid: Boolean? by lazy {
        catchingUnwrapped { Asn1String.decodeFromTlv(value.asPrimitive()).isValid }.getOrNull()
    }

    init {
        if (validateValue && isValid == false) {
            throw Asn1Exception("Invalid AttributeTypeAndValue: ${providedContent?.first} ${displayName?.let { "($it)" }} for value ${providedContent?.second}!")
        }
    }

    class CommonName : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.COMMON_NAME)!! }
    }

    class Country : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.COUNTRY)!! }
    }

    class Locality : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.LOCALITY)!! }
    }

    class StateOrProvince : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.STATE_OR_PROVINCE)!! }
    }

    class Organization : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.ORGANIZATION)!! }
    }

    class OrganizationalUnit : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.ORGANIZATIONAL_UNIT)!! }
    }

    class Title : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.TITLE)!! }
    }

    class Street : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.STREET)!! }
    }

    class DomainComponent : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.DOMAIN_COMPONENT)!! }
    }

    class DistinguishedNameQualifier : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.DISTINGUISHED_NAME_QUALIFIER)!! }
    }

    class Surname : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.SURNAME)!! }
    }

    class GivenName : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.GIVEN_NAME)!! }
    }

    class Initials : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.INITIALS)!! }
    }

    class Generation : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.GENERATION)!! }
    }

    class EmailAddress : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.EMAIL_ADDRESS)!! }
    }

    class UserId : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.USER_ID)!! }
    }

    class SerialNumber : AttributeTypeAndValue {
        constructor(value: Asn1Element) : super(OID, value)
        constructor(value: Asn1String) : super(OID, value)
        constructor(str: String) : this(Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object { val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.SERIAL_NUMBER)!! }
    }

    fun toRfc2253String(): String {
        val attrValue = (value as? Asn1Primitive)?.let { prim ->
            runCatching {
                var decodedValue = Asn1String.decodeFromTlv(prim).value
                val wasQuoted = decodedValue.startsWith("\"") && decodedValue.endsWith("\"")
                decodedValue = decodedValue.removeSurrounding("\"")
                val wasBackslashFirst = decodedValue.startsWith("\\")
                val unescaped = decodedValue.replace("""\\(.)""".toRegex(), "$1")
                canonicalizeString(unescaped, wasQuoted, wasBackslashFirst)
            }.getOrElse { "#" + prim.content.toHexString() }
        } ?: ("#" + value.derEncoded.toHexString())

        return "${AttributeTypeOidMap.nameFor(oid) ?: oid}=$attrValue".lowercase()
    }

    private fun canonicalizeString(input: String, wasQuoted: Boolean, wasBackSlashFirst: Boolean): String {
        if (input.isEmpty()) return ""
        if (wasQuoted) return input.trim().replace(Regex("\\s+"), " ")
        val escapees = ",+<>;\"\\="
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

    override fun toString() = "AttributeTypeAndValue(oid=$oid, value=$value)"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttributeTypeAndValue) return false
        return asn1Representation == other.asn1Representation
    }

    override fun hashCode(): Int = asn1Representation.hashCode()

    companion object : DerDecodable<X500AttributeTypeAndValue, AttributeTypeAndValue> {

        override fun decodeFromTlv(
            serializer: KSerializer<X500AttributeTypeAndValue>,
            src: Asn1Element,
            der: Der,
        ): AttributeTypeAndValue =
            fromAsn1Representation(der.decodeFromTlv(serializer, src))

        fun fromString(type: String, value: String): AttributeTypeAndValue? {
            val asn1String = Asn1String.UTF8(value.trim())
            return when (type.uppercase()) {
                AttributeTypeOidMap.COMMON_NAME -> CommonName(asn1String)
                AttributeTypeOidMap.COUNTRY -> Country(asn1String)
                AttributeTypeOidMap.LOCALITY -> Locality(asn1String)
                AttributeTypeOidMap.STATE_OR_PROVINCE_ALIAS, AttributeTypeOidMap.STATE_OR_PROVINCE ->
                    StateOrProvince(asn1String)

                AttributeTypeOidMap.ORGANIZATION -> Organization(asn1String)
                AttributeTypeOidMap.ORGANIZATIONAL_UNIT -> OrganizationalUnit(asn1String)
                AttributeTypeOidMap.TITLE -> Title(asn1String)
                AttributeTypeOidMap.STREET -> Street(asn1String)
                AttributeTypeOidMap.DOMAIN_COMPONENT -> DomainComponent(asn1String)
                AttributeTypeOidMap.DISTINGUISHED_NAME_QUALIFIER_ALIAS,
                AttributeTypeOidMap.DISTINGUISHED_NAME_QUALIFIER -> DistinguishedNameQualifier(asn1String)

                AttributeTypeOidMap.SURNAME -> Surname(asn1String)
                AttributeTypeOidMap.GIVEN_NAME -> GivenName(asn1String)
                AttributeTypeOidMap.INITIALS -> Initials(asn1String)
                AttributeTypeOidMap.GENERATION -> Generation(asn1String)
                AttributeTypeOidMap.EMAIL_ALIAS, AttributeTypeOidMap.EMAIL_ADDRESS -> EmailAddress(asn1String)
                AttributeTypeOidMap.USER_ID -> UserId(asn1String)
                AttributeTypeOidMap.SERIAL_NUMBER -> SerialNumber(asn1String)
                else -> null
            }
        }

        fun fromAsn1Representation(asn1Representation: X500AttributeTypeAndValue): AttributeTypeAndValue =
            when (asn1Representation.oid) {
                CommonName.OID -> CommonName(asn1Representation)
                Country.OID -> Country(asn1Representation)
                Locality.OID -> Locality(asn1Representation)
                StateOrProvince.OID -> StateOrProvince(asn1Representation)
                Organization.OID -> Organization(asn1Representation)
                OrganizationalUnit.OID -> OrganizationalUnit(asn1Representation)
                Title.OID -> Title(asn1Representation)
                Street.OID -> Street(asn1Representation)
                DomainComponent.OID -> DomainComponent(asn1Representation)
                DistinguishedNameQualifier.OID -> DistinguishedNameQualifier(asn1Representation)
                Surname.OID -> Surname(asn1Representation)
                GivenName.OID -> GivenName(asn1Representation)
                Initials.OID -> Initials(asn1Representation)
                Generation.OID -> Generation(asn1Representation)
                EmailAddress.OID -> EmailAddress(asn1Representation)
                UserId.OID -> UserId(asn1Representation)
                SerialNumber.OID -> SerialNumber(asn1Representation)
                else -> AttributeTypeAndValue(asn1Representation)
            }
    }
}

object AttributeTypeOidMap {
    const val COMMON_NAME = "CN"
    const val COUNTRY = "C"
    const val LOCALITY = "L"
    const val STATE_OR_PROVINCE_ALIAS = "S"
    const val STATE_OR_PROVINCE = "ST"
    const val ORGANIZATION = "O"
    const val ORGANIZATIONAL_UNIT = "OU"
    const val TITLE = "T"
    const val STREET = "STREET"
    const val DOMAIN_COMPONENT = "DC"
    const val DISTINGUISHED_NAME_QUALIFIER = "DNQUALIFIER"
    const val DISTINGUISHED_NAME_QUALIFIER_ALIAS = "DNQ"
    const val SURNAME = "SURNAME"
    const val GIVEN_NAME = "GIVENNAME"
    const val INITIALS = "INITIALS"
    const val GENERATION = "GENERATION"
    const val EMAIL_ALIAS = "EMAIL"
    const val EMAIL_ADDRESS = "EMAILADDRESS"
    const val USER_ID = "UID"
    const val SERIAL_NUMBER = "SERIALNUMBER"

    private val nameToOid: Map<String, ObjectIdentifier> = mapOf(
        COMMON_NAME to ObjectIdentifier("2.5.4.3"),
        COUNTRY to ObjectIdentifier("2.5.4.6"),
        LOCALITY to ObjectIdentifier("2.5.4.7"),
        STATE_OR_PROVINCE to ObjectIdentifier("2.5.4.8"),
        ORGANIZATION to ObjectIdentifier("2.5.4.10"),
        ORGANIZATIONAL_UNIT to ObjectIdentifier("2.5.4.11"),
        TITLE to ObjectIdentifier("2.5.4.12"),
        STREET to ObjectIdentifier("2.5.4.9"),
        DOMAIN_COMPONENT to ObjectIdentifier("0.9.2342.19200300.100.1.25"),
        DISTINGUISHED_NAME_QUALIFIER to ObjectIdentifier("2.5.4.46"),
        SURNAME to ObjectIdentifier("2.5.4.4"),
        GIVEN_NAME to ObjectIdentifier("2.5.4.42"),
        INITIALS to ObjectIdentifier("2.5.4.43"),
        GENERATION to ObjectIdentifier("2.5.4.44"),
        EMAIL_ADDRESS to ObjectIdentifier("1.2.840.113549.1.9.1"),
        USER_ID to ObjectIdentifier("0.9.2342.19200300.100.1.1"),
        SERIAL_NUMBER to ObjectIdentifier("2.5.4.5"),
    )

    private val oidToName: Map<ObjectIdentifier, String> =
        nameToOid.entries.associate { (name, oid) -> oid to name }

    fun oidFor(name: String): ObjectIdentifier? =
        nameToOid[name.uppercase()]

    fun nameFor(oid: ObjectIdentifier): String? =
        oidToName[oid]
}
