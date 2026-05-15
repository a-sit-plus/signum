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
        X500RelativeDistinguishedName(attrsAndValues.map { it.requireX509().asn1Representation }.toSet())
    }

    val attrsAndValues: Set<AttributeTypeAndValue> by providedAttrsAndValues orLazy {
        asn1Representation.attrsAndValues.map(AttributeTypeAndValue::fromAsn1Representation).toSet()
    }

    val isValid: Boolean by lazy { attrsAndValues.all { it.isValid != false } }

    init {
        if (performValidation) {
            providedAttrsAndValues?.validate()
            if (!isValid) throw Asn1Exception("Invalid RelativeDistinguishedName!")
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RelativeDistinguishedName) return false
        return attrsAndValues == other.attrsAndValues
    }

    override fun hashCode(): Int = attrsAndValues.hashCode()

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

private fun Set<AttributeTypeAndValue>.validate() {
    if (isEmpty()) throw Asn1Exception("RelativeDistinguishedName must contain at least one AttributeTypeAndValue")

    groupBy { it.oid }.forEach { (oid, attrs) ->
        if (attrs.size > 1) {
            throw Asn1Exception("RelativeDistinguishedName contains multiple values for attribute OID $oid")
        }
    }
}

sealed interface AttributeTypeAndValue : Identifiable {
    val displayName: String?
    val isValid: Boolean?

    /**
     * Converts the current AttributeTypeAndValue instance into a string representation
     * that conforms to the RFC 2253 standard for Distinguished Names (DNs).
     *
     * @return A string representation of the attribute's type and value in RFC 2253 format.
     * @throws Asn1Exception if the attribute has no X.509 representation (i.e. if it does not implement [X509Representable]),
     * as the RFC only defines string canonicalization for X.509
     */
    fun toRfc2253String(): String = requireX509().toRfc2253String()

    interface X509Representable : AttributeTypeAndValue, DerEncodable<X500AttributeTypeAndValue> {
        val value: Asn1Element

        override fun toRfc2253String(): String {
            val attrValue = (value as? Asn1Primitive)?.let { prim ->
                catchingUnwrapped {
                    var decodedValue = Asn1String.decodeFromTlv(prim).value
                    val wasQuoted = decodedValue.startsWith("\"") && decodedValue.endsWith("\"")
                    decodedValue = decodedValue.removeSurrounding("\"")
                    val wasBackslashFirst = decodedValue.startsWith("\\")
                    val unescaped = decodedValue.replace("""\\(.)""".toRegex(), "$1")
                    canonicalizeRfc2253String(unescaped, wasQuoted, wasBackslashFirst)
                }.getOrElse { "#" + prim.toDerHexString() }
            } ?: ("#" + value.derEncoded.toHexString())

            return "${Registry.nameFor(oid)?.lowercase() ?: oid}=$attrValue"
        }
    }

    interface Descriptor : Identifiable {
        val canonicalName: String
        val aliases: Set<String>

        fun fromString(value: String): AttributeTypeAndValue
        fun fromAsn1Representation(src: X500AttributeTypeAndValue): X509Representable

        fun register(): Descriptor = Registry.register(this)
    }

    object Registry {
        private val descriptors = hashMapOf<ObjectIdentifier, Descriptor>()
        private var defaultsRegistered = false

        fun register(descriptor: Descriptor): Descriptor {
            descriptors[descriptor.oid] = descriptor
            return descriptor
        }

        fun oidFor(name: String): ObjectIdentifier? =
            descriptorForName(name)?.oid

        fun nameFor(oid: ObjectIdentifier): String? =
            descriptorFor(oid)?.canonicalName

        fun descriptorFor(oid: ObjectIdentifier): Descriptor? {
            ensureDefaultsRegistered()
            return descriptors[oid]
        }

        fun descriptorForName(name: String): Descriptor? {
            ensureDefaultsRegistered()
            val normalizedName = name.uppercase()
            return descriptors.values.firstOrNull {
                it.canonicalName.uppercase() == normalizedName || it.aliases.any { alias -> alias.uppercase() == normalizedName }
            }
        }

        private fun ensureDefaultsRegistered() {
            if (defaultsRegistered) return
            defaultsRegistered = true
            listOf(
                CommonName,
                Country,
                Locality,
                StateOrProvince,
                Organization,
                OrganizationalUnit,
                Title,
                Street,
                DomainComponent,
                DistinguishedNameQualifier,
                Surname,
                GivenName,
                Initials,
                Generation,
                EmailAddress,
                UserId,
                SerialNumber,
            ).forEach { register(it) }
        }
    }

    class CommonName : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.3")
           
            override val canonicalName = "CN"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = CommonName(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = CommonName(src)
        }
    }

    class Country : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.6")
           
            override val canonicalName = "C"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = Country(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Country(src)
        }
    }

    class Locality : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.7")
           
            override val canonicalName = "L"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = Locality(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Locality(src)
        }
    }

    class StateOrProvince : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid,Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.8")
           
            override val canonicalName = "ST"
            override val aliases = setOf("S")
            init { register() }
            override fun fromString(value: String) = StateOrProvince(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = StateOrProvince(src)
        }
    }

    class Organization : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid,Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.10")
           
            override val canonicalName = "O"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = Organization(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Organization(src)
        }
    }

    class OrganizationalUnit : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid,Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.11")
           
            override val canonicalName = "OU"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = OrganizationalUnit(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = OrganizationalUnit(src)
        }
    }

    class Title : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.12")
           
            override val canonicalName = "T"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = Title(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Title(src)
        }
    }

    class Street : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.9")
           
            override val canonicalName = "STREET"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = Street(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Street(src)
        }
    }

    class DomainComponent : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.IA5(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("0.9.2342.19200300.100.1.25")
           
            override val canonicalName = "DC"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = DomainComponent(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = DomainComponent(src)
        }
    }

    class DistinguishedNameQualifier : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.46")
           
            override val canonicalName = "DNQUALIFIER"
            override val aliases = setOf("DNQ")
            init { register() }
            override fun fromString(value: String) = DistinguishedNameQualifier(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = DistinguishedNameQualifier(src)
        }
    }

    class Surname : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid,Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.4")
           
            override val canonicalName = "SURNAME"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = Surname(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Surname(src)
        }
    }

    class GivenName : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.42")
           
            override val canonicalName = "GIVENNAME"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = GivenName(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = GivenName(src)
        }
    }

    class Initials : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid,Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.43")
           
            override val canonicalName = "INITIALS"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = Initials(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Initials(src)
        }
    }

    class Generation : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.44")
           
            override val canonicalName = "GENERATION"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = Generation(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = Generation(src)
        }
    }

    class EmailAddress : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.IA5(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("1.2.840.113549.1.9.1")
           
            override val canonicalName = "EMAILADDRESS"
            override val aliases = setOf("EMAIL")
            init { register() }
            override fun fromString(value: String) = EmailAddress(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = EmailAddress(src)
        }
    }

    class UserId : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid,Asn1String.UTF8(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("0.9.2342.19200300.100.1.1")
           
            override val canonicalName = "UID"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = UserId(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = UserId(src)
        }
    }

    class SerialNumber : BaseX509AttributeTypeAndValue {
        constructor(str: String) : super(Companion.oid, Asn1String.Printable(str))
        internal constructor(asn1Representation: X500AttributeTypeAndValue) : super(asn1Representation)
        companion object : Descriptor {
            override val oid = ObjectIdentifier("2.5.4.5")
           
            override val canonicalName = "SERIALNUMBER"
            override val aliases = emptySet<String>()
            init { register() }
            override fun fromString(value: String) = SerialNumber(value)
            override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = SerialNumber(src)
        }
    }

    companion object : DerDecodable<X500AttributeTypeAndValue, X509Representable> {

        operator fun invoke(oid: ObjectIdentifier, value: Asn1Element): X509Representable =
            fromAsn1Representation(X500AttributeTypeAndValue(oid, value))

        operator fun invoke(asn1Representation: X500AttributeTypeAndValue): X509Representable =
            fromAsn1Representation(asn1Representation)

        override fun decodeFromTlv(
            serializer: KSerializer<X500AttributeTypeAndValue>,
            src: Asn1Element,
            der: Der,
        ): X509Representable =
            fromAsn1Representation(der.decodeFromTlv(serializer, src))

        fun fromString(type: String, value: String): AttributeTypeAndValue? =
            Registry.descriptorForName(type)?.fromString(value.trim())

        fun fromAsn1Representation(asn1Representation: X500AttributeTypeAndValue): X509Representable =
            Registry.descriptorFor(asn1Representation.oid)?.fromAsn1Representation(asn1Representation)
                ?: BaseX509AttributeTypeAndValue(asn1Representation)
    }
}



abstract class BaseAttributeTypeAndValue(
    override val oid: ObjectIdentifier,
) : AttributeTypeAndValue {
    override val displayName: String? get() = AttributeTypeAndValue.Registry.nameFor(oid)
    override val isValid: Boolean? = null

    override fun toString() = "AttributeTypeAndValue(oid=$oid)"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttributeTypeAndValue) return false
        return oid == other.oid
    }

    override fun hashCode(): Int = oid.hashCode()
}

open class BaseX509AttributeTypeAndValue protected constructor(
    providedAsn1Representation: X500AttributeTypeAndValue?,
    oid: ObjectIdentifier,
    override val value: Asn1Element,
    validateValue: Boolean,
) : BaseAttributeTypeAndValue(oid), AttributeTypeAndValue.X509Representable {

    constructor(oid: ObjectIdentifier, value: Asn1Element) : this(null, oid, value, false)

    @Throws(Asn1Exception::class)
    constructor(oid: ObjectIdentifier, value: Asn1String) : this(null, oid, value.encodeToTlv(), true)

    internal constructor(asn1Representation: X500AttributeTypeAndValue) :
            this(asn1Representation, asn1Representation.oid, asn1Representation.value, false)

    override val asn1Representation: X500AttributeTypeAndValue by providedAsn1Representation orLazy {
        X500AttributeTypeAndValue(oid, value)
    }

    override val isValid: Boolean? by lazy {
        catchingUnwrapped { Asn1String.decodeFromTlv(value.asPrimitive()).isValid }.getOrNull()
    }

    init {
        if (validateValue && isValid == false) {
            throw Asn1Exception("Invalid AttributeTypeAndValue: ${displayName?.let { "($it)" }}!")
        }
    }

    override fun toString() = "AttributeTypeAndValue(oid=$oid, value=$value)"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BaseX509AttributeTypeAndValue) return false
        return oid == other.oid && value == other.value
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }
}

private fun canonicalizeRfc2253String(input: String, wasQuoted: Boolean, wasBackSlashFirst: Boolean): String {
    if (input.isEmpty()) return ""
    if (wasQuoted) return input.trim().replace(Regex("\\s+"), " ")
    val escapees = ",+<>;\"\\="
    return buildString {
        var previousWasSpace = false
        var startIndex = 0

        if (input.startsWith("#")) {
            val hexPart = input.drop(1)
            val isHex = hexPart.length % 2 == 0 && hexPart.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
            if (isHex && !wasBackSlashFirst) {
                append('#')
                startIndex = 1
            } else {
                append('\\').append('#')
                startIndex = 1
            }
        }

        input.drop(startIndex).forEachIndexed { index, c ->
            when {
                c == ' ' && index == 0 -> {
                    append("\\ ")
                    previousWasSpace = true
                }

                c == ' ' && index == input.lastIndex - startIndex -> append("\\ ")

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

private fun AttributeTypeAndValue.requireX509(): AttributeTypeAndValue.X509Representable =
    this as? AttributeTypeAndValue.X509Representable
        ?: throw Asn1Exception("Attribute $oid has no X.509/DER representation")
