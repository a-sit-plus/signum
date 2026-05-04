package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.serialization.OidProvider
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Awesn1Backed
import at.asitplus.signum.indispensable.asn1.Awesn1BackedSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlin.text.toHexString

/**
 * X.500 Name (used in X.509 Certificates)
 */
@Serializable(with = RelativeDistinguishedName.Companion::class)
class RelativeDistinguishedName(
    override val backing: X500RelativeDistinguishedName,
    performValidation: Boolean
) : Awesn1Backed<X500RelativeDistinguishedName> {

    val isValid: Boolean by lazy {
        backing.attrsAndValues.map { AttributeTypeAndValue(it) }.all { it.isValid == true }
    }


    val attrsAndValues: List<AttributeTypeAndValue> by lazy {backing.attrsAndValues.map { AttributeTypeAndValue(it) } }
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
@Serializable(with = AttributeTypeAndValue.Companion::class)
open class AttributeTypeAndValue(
    override val backing: X500AttributeTypeAndValue
) : Identifiable, Awesn1Backed<X500AttributeTypeAndValue> {

    override val oid: ObjectIdentifier get() = backing.oid

    val rawValue get() = backing.value

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

    abstract class BackingSerializer<Wrapper : AttributeTypeAndValue>(
        expectedOid: ObjectIdentifier,
        private val wrap: (X500AttributeTypeAndValue) -> Wrapper,
    ) : Awesn1BackedSerializer<X500AttributeTypeAndValue, Wrapper>(
        X500AttributeTypeAndValue.serializer(), { backing ->
            if (backing.oid != expectedOid) {
                throw SerializationException("Unexpected AttributeTypeAndValue OID ${backing.oid}, expected $expectedOid")
            }
            wrap(backing)
        },
    ), OidProvider<Wrapper> {
        final override val oid: ObjectIdentifier = expectedOid
    }

    @Serializable(with = CommonName.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<CommonName>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.COMMON_NAME)!!,
            ::CommonName,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.COMMON_NAME)!!
        }
    }

    @Serializable(with = Country.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<Country>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.COUNTRY)!!,
            ::Country,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.COUNTRY)!!
        }
    }

    @Serializable(with = Locality.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<Locality>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.LOCALITY)!!,
            ::Locality,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.LOCALITY)!!
        }
    }

    @Serializable(with = StateOrProvince.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<StateOrProvince>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.STATE_OR_PROVINCE)!!,
            ::StateOrProvince,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.STATE_OR_PROVINCE)!!
        }
    }

    @Serializable(with = Organization.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<Organization>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.ORGANIZATION)!!,
            ::Organization,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.ORGANIZATION)!!
        }
    }

    @Serializable(with = OrganizationalUnit.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<OrganizationalUnit>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.ORGANIZATIONAL_UNIT)!!,
            ::OrganizationalUnit,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.ORGANIZATIONAL_UNIT)!!
        }
    }

    @Serializable(with = Title.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<Title>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.TITLE)!!,
            ::Title,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.TITLE)!!
        }
    }

    @Serializable(with = Street.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<Street>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.STREET)!!,
            ::Street,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.STREET)!!
        }
    }

    @Serializable(with = DomainComponent.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<DomainComponent>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.DOMAIN_COMPONENT)!!,
            ::DomainComponent,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.DOMAIN_COMPONENT)!!
        }
    }

    @Serializable(with = DistinguishedNameQualifier.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<DistinguishedNameQualifier>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.DISTINGUISHED_NAME_QUALIFIER)!!,
            ::DistinguishedNameQualifier,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.DISTINGUISHED_NAME_QUALIFIER)!!
        }
    }

    @Serializable(with = Surname.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<Surname>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.SURNAME)!!,
            ::Surname,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.SURNAME)!!
        }
    }

    @Serializable(with = GivenName.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<GivenName>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.GIVEN_NAME)!!,
            ::GivenName,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.GIVEN_NAME)!!
        }
    }

    @Serializable(with = Initials.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<Initials>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.INITIALS)!!,
            ::Initials,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.INITIALS)!!
        }
    }

    @Serializable(with = Generation.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<Generation>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.GENERATION)!!,
            ::Generation,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.GENERATION)!!
        }
    }

    @Serializable(with = EmailAddress.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<EmailAddress>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.EMAIL_ADDRESS)!!,
            ::EmailAddress,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.EMAIL_ADDRESS)!!
        }
    }

    @Serializable(with = UserId.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<UserId>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.USER_ID)!!,
            ::UserId,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.USER_ID)!!
        }
    }

    @Serializable(with = SerialNumber.Companion::class)
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

        internal constructor(backing: X500AttributeTypeAndValue) : this(Asn1String.decodeFromTlv(backing.value.asPrimitive()))

        companion object : BackingSerializer<SerialNumber>(
            AttributeTypeOidMap.oidFor(AttributeTypeOidMap.SERIAL_NUMBER)!!,
            ::SerialNumber,
        ) {
            val OID = AttributeTypeOidMap.oidFor(AttributeTypeOidMap.SERIAL_NUMBER)!!
        }
    }

    companion object: Awesn1BackedSerializer<X500AttributeTypeAndValue, AttributeTypeAndValue>(X500AttributeTypeAndValue.serializer(),
         AttributeTypeAndValue::fromBacking) {

        /**
         * Parse an individual type=value string into the correct AttributeTypeAndValue subclass.
         *
         * @return null if none fits
         */
        fun fromString(type: String, value: String): AttributeTypeAndValue? {
            val trimmed = value.trim()
            val asn1String = Asn1String.UTF8(trimmed)

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

        /**
         * Wrap an already-decoded X500AttributeTypeAndValue in the matching subclass.
         */
        fun fromBacking(backing: X500AttributeTypeAndValue): AttributeTypeAndValue =
            when (backing.oid) {
                CommonName.OID -> CommonName(backing)
                Country.OID -> Country(backing)
                Locality.OID -> Locality(backing)
                StateOrProvince.OID -> StateOrProvince(backing)
                Organization.OID -> Organization(backing)
                OrganizationalUnit.OID -> OrganizationalUnit(backing)
                Title.OID -> Title(backing)
                Street.OID -> Street(backing)
                DomainComponent.OID -> DomainComponent(backing)
                DistinguishedNameQualifier.OID -> DistinguishedNameQualifier(backing)
                Surname.OID -> Surname(backing)
                GivenName.OID -> GivenName(backing)
                Initials.OID -> Initials(backing)
                Generation.OID -> Generation(backing)
                EmailAddress.OID -> EmailAddress(backing)
                UserId.OID -> UserId(backing)
                SerialNumber.OID -> SerialNumber(backing)
                else -> AttributeTypeAndValue(backing)
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

    val ORDER = listOf(
        COMMON_NAME, COUNTRY, LOCALITY, STATE_OR_PROVINCE_ALIAS, STATE_OR_PROVINCE,
        ORGANIZATION, ORGANIZATIONAL_UNIT, TITLE, STREET, DOMAIN_COMPONENT,
        DISTINGUISHED_NAME_QUALIFIER, DISTINGUISHED_NAME_QUALIFIER_ALIAS, SURNAME,
        GIVEN_NAME, INITIALS, GENERATION, EMAIL_ALIAS, EMAIL_ADDRESS, USER_ID,
        SERIAL_NUMBER,
    ).withIndex().associate { it.value.uppercase() to it.index }
}
