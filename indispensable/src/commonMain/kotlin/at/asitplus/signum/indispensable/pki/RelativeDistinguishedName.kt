package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.serialization.Der
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.internals.orLazy
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
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

    /**
     * Convenience: a single-attribute RDN from an awesn1 [X500AttributeTypeAndValue], e.g.
     * `RelativeDistinguishedName(X500AttributeTypeAndValue.CommonName("ACME"))`. Wraps it in the
     * generic bridge [AttributeTypeAndValue] so callers needn't depend on the typed attributes in
     * `indispensable-pkix`.
     */
    constructor(singleItem: X500AttributeTypeAndValue) : this(AttributeTypeAndValue(singleItem))

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

    companion object : DerDecodable<X500RelativeDistinguishedName, RelativeDistinguishedName> {

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
    isNotEmpty() && groupBy { it.oid }.none { it.value.size > 1 }

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
            // The stored value is raw (unescaped); re-escape per RFC 4514 for output. Non-string or
            // undecodable values fall back to the hexstring form.
            val attrValue = (value as? Asn1Primitive)?.let { prim ->
                catchingUnwrapped { canonicalizeRfc2253String(Asn1String.decodeFromTlv(prim).value) }
                    .getOrElse { "#" + prim.toDerHexString() }
            } ?: ("#" + value.derEncoded.toHexString())

            // RFC 2253 canonical form for case-insensitive matching: fold the value to lower case too
            return "${Registry.nameFor(oid)?.lowercase() ?: oid}=${attrValue.lowercase()}"
        }
    }

    interface Descriptor : Identifiable {
        val canonicalName: String
        val aliases: Set<String>

        fun fromString(value: String): AttributeTypeAndValue
        fun fromAsn1Representation(src: X500AttributeTypeAndValue): X509Representable

        fun register(): Descriptor = Registry.register(this)
    }

    /**
     * Maps attribute OIDs to their typed [Descriptor]s (and powers RFC 4514 keyword lookup).
     *
     * Registration is **startup-only**: descriptors must be registered (via [register], e.g. from
     * `SignumPkix.install()`) **before the first (de)serialization**. The registry seals on its first
     * lookup — after that it is immutable and reads are lock-free; later [register] calls throw. This
     * mirrors the `DefaultDer.register` contract and removes the former runtime-mutable machinery.
     */
    @OptIn(ExperimentalAtomicApi::class)
    object Registry {
        private val descriptors = hashMapOf<ObjectIdentifier, Descriptor>()
        private val sealed = AtomicReference<Map<ObjectIdentifier, Descriptor>?>(null)

        fun register(descriptor: Descriptor): Descriptor {
            check(sealed.load() == null) {
                "AttributeTypeAndValue registry is sealed; register before the first (de)serialization."
            }
            descriptors[descriptor.oid] = descriptor
            return descriptor
        }

        fun oidFor(name: String): ObjectIdentifier? =
            descriptorForName(name)?.oid

        fun nameFor(oid: ObjectIdentifier): String? =
            descriptorFor(oid)?.canonicalName

        fun descriptorFor(oid: ObjectIdentifier): Descriptor? = view()[oid]

        fun descriptorForName(name: String): Descriptor? {
            val normalizedName = name.uppercase()
            return view().values.firstOrNull {
                it.canonicalName.uppercase() == normalizedName ||
                        it.aliases.any { alias -> alias.uppercase() == normalizedName }
            }
        }

        private fun view(): Map<ObjectIdentifier, Descriptor> =
            sealed.load() ?: descriptors.toMap().also { sealed.store(it) }
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

        @OptIn(ExperimentalStdlibApi::class)
        fun fromString(type: String, value: String): AttributeTypeAndValue? {
            val key = type.trim()
            val v = value.trim()
            // RFC 4514 §2.4 hexstring form: the value is its DER encoding in hex (e.g. "#130138").
            if (v.length > 1 && v.first() == '#' &&  isHexString(v.substring(1))) {
                catchingUnwrapped { Asn1Element.parse(v.substring(1).hexToByteArray()) }.getOrNull()?.let { element ->
                    val oid = Registry.descriptorForName(key)?.oid
                        ?: catchingUnwrapped { ObjectIdentifier(key) }.getOrNull() ?: return null
                    return invoke(oid, element)
                }
            }
            // Otherwise unquote/unescape to the raw value; the typed Asn1String holds the raw content,
            // and toRfc2253String re-escapes on output (RFC 4514). This keeps the stored value correct
            // (no escape backslashes in the DER) and works for PrintableString/IA5 attributes too.
            val raw = unescapeRfc2253(v)
            Registry.descriptorForName(key)?.let { return it.fromString(raw) }
            // Fall back to a raw dotted-OID attribute type (e.g. "1.2.3.4.5"); value carried as a UTF8String.
            val oid = catchingUnwrapped { ObjectIdentifier(key) }.getOrNull() ?: return null
            return invoke(oid, Asn1String.UTF8(raw).encodeToTlv())
        }

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

    override fun toString() = "AttributeTypeAndValue(${displayName?:""} oid=$oid})"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        other as BaseAttributeTypeAndValue
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

    constructor(asn1Representation: X500AttributeTypeAndValue) :
            this(asn1Representation, asn1Representation.oid, asn1Representation.value, false)

    override val asn1Representation: X500AttributeTypeAndValue by providedAsn1Representation orLazy {
        X500AttributeTypeAndValue(oid, value)
    }

    override val isValid: Boolean? by lazy {
        catchingUnwrapped { Asn1String.decodeFromTlv(value.asPrimitive()).isValid }.getOrElse { false }
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

private fun AttributeTypeAndValue.requireX509(): AttributeTypeAndValue.X509Representable =
    this as? AttributeTypeAndValue.X509Representable
        ?: throw Asn1Exception("Attribute $oid has no X.509/DER representation")
