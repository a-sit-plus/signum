package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.TagClass
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

//TODO TODO TODO: Still needs to be ridden of ASN.1 specifics and made more generic! Still stays here for now a s plug for pkix extension module

/** Builds an IMPLICIT context-specific primitive tag for a GeneralName CHOICE alternative. */
fun contextTag(value: ULong) = Asn1Element.Tag(value, constructed = false, TagClass.CONTEXT_SPECIFIC)

/**
 * An RFC 5280 `GeneralName` CHOICE.
 *
 * The lean core parses **any** alternative generically, keeping the verbatim CHOICE-tagged DER in
 * [encoded] so it always round-trips. The **typed** variants (`DNSName`, `IPAddressName`, …) live in
 * `indispensable-pkix` as subclasses that self-register a [Descriptor] keyed by [NameType]; once
 * `SignumPkix.install()` has run, [decodeFromTlv] upgrades a generic [GeneralName] to its typed
 * subclass. Mirrors the [at.asitplus.signum.indispensable.pki.CertificateExtension] pattern.
 */
open class GeneralName(
    val type: NameType,
    /** The full CHOICE-tagged DER element — the single source of truth for re-encoding. */
    protected val encoded: Asn1Element,
) : Asn1Encodable<Asn1Element> {

    enum class NameType(val value: ULong) {
        OTHER(0u), RFC822(1u), DNS(2u), X400(3u), DIRECTORY(4u), EDI(5u), URI(6u), IP(7u), OID(8u);

        companion object {
            fun fromTagValue(tagValue: ULong): NameType? = entries.firstOrNull { it.value == tagValue }
        }
    }

    enum class ConstraintResult {
        DIFF_TYPE,     // Different type, no constraint
        MATCH,         // Exact match
        NARROWS,       // Input narrows this name
        WIDENS,        // Input widens this name
        SAME_TYPE;     // Same type, but no match/narrow/widen
    }

    /**
     * Returns whether this name is valid:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented (the generic [GeneralName] never validates)
     */
    open val isValid: Boolean? get() = null

    final override fun encodeToTlv(): Asn1Element = encoded

    @ExperimentalPkiApi
    open fun constrains(input: GeneralName?): ConstraintResult {
        when {
            input == null || this::class != input::class -> return ConstraintResult.DIFF_TYPE

            isValid == null || input.isValid == null ->
                throw IllegalArgumentException(
                    "${this::class.simpleName} does not support validation out of the box. " +
                            "You must explicitly provide custom validation logic using " +
                            "${this::class.simpleName}.createValidatedCopy { /* validation logic */ } before calling constrains."
                )

            !isValid!! || !input.isValid!! -> throw Asn1Exception("Invalid ${this::class.simpleName}")

            else -> throw UnsupportedOperationException(
                "Narrows, widens and match are not yet implemented for ${this::class.simpleName}."
            )
        }
    }

    /**
     * Returns a copy of this name with `isValid` set per [validate]. Intended for variants that do
     * not implement validation (`isValid == null`), to mark them before constraint checks.
     */
    open fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName =
        throw IllegalArgumentException()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GeneralName) return false
        return type == other.type && encoded == other.encoded
    }

    override fun hashCode(): Int = 31 * type.hashCode() + encoded.hashCode()

    override fun toString(): String = "GeneralName(type=$type, value=$encoded)"

    /**
     * Describes a typed [GeneralName] alternative and constructs it from the generic CHOICE-tagged
     * element. Register custom alternatives via [register]. Mirrors
     * [at.asitplus.signum.indispensable.pki.CertificateExtension.Descriptor].
     */
    interface Descriptor {
        val type: NameType
        fun fromTagged(src: Asn1Element): GeneralName
        fun register(): Descriptor = Registry.register(this)
    }

    /**
     * Maps GeneralName CHOICE [NameType]s to their typed [Descriptor]s for the decode upgrade path.
     *
     * Registration is **startup-only**: descriptors must be registered (via [register], e.g. from
     * `SignumPkix.install()`) **before the first (de)serialization**. The registry seals on its first
     * lookup — after that it is immutable and reads are lock-free; later [register] calls throw.
     */
    @OptIn(ExperimentalAtomicApi::class)
    object Registry {
        private val descriptors = hashMapOf<NameType, Descriptor>()
        private val sealed = AtomicReference<Map<NameType, Descriptor>?>(null)

        fun register(descriptor: Descriptor): Descriptor {
            check(sealed.load() == null) {
                "GeneralName registry is sealed; register before the first (de)serialization."
            }
            descriptors[descriptor.type] = descriptor
            return descriptor
        }

        fun descriptorFor(type: NameType): Descriptor? = view()[type]

        private fun view(): Map<NameType, Descriptor> =
            sealed.load() ?: descriptors.toMap().also { sealed.store(it) }
    }

    companion object : Asn1Decodable<Asn1Element, GeneralName> {
        /**
         * Decodes a `GeneralName`, upgrading to a registered typed variant when one is registered for
         * the CHOICE tag (and decoding succeeds), else returning a generic [GeneralName] carrying the
         * verbatim element. A typed-decode failure falls back to the generic form rather than throwing.
         */
        override fun doDecode(src: Asn1Element): GeneralName {
            val type = NameType.fromTagValue(src.tag.tagValue)
                ?: throw Asn1Exception("Unsupported GeneralName tag ${src.tag}")
            return Registry.descriptorFor(type)
                ?.let { catchingUnwrapped { it.fromTagged(src) }.getOrNull() }
                ?: GeneralName(type, src)
        }
    }
}
