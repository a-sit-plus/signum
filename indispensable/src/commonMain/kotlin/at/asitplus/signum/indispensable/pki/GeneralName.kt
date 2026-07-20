package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.TagClass
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/** An encoding-independent RFC 5280/C509 `GeneralName`. */
interface GeneralName {

    val type: NameType

    /** A [GeneralName] with an ASN.1/DER X.509 representation. */
    interface X509Representable : GeneralName, DerEncodable<Asn1Element> {

        interface Descriptor {
            val type: NameType
            fun fromAsn1Representation(src: Asn1Element): X509Representable
            fun register(): Descriptor = Registry.register(this)
        }

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

        companion object {
            fun fromAsn1Representation(type: NameType, src: Asn1Element): X509Representable {
                if (src.tag.tagClass != TagClass.CONTEXT_SPECIFIC || src.tag.tagValue != type.value) {
                    throw Asn1Exception("GeneralName $type has an invalid tag: ${src.tag}")
                }
                val expectedConstructed = when (type) {
                    NameType.OTHER, NameType.X400, NameType.DIRECTORY, NameType.EDI -> true
                    else -> false
                }
                //is this too strict? I fear it might be…
                //then again, a basic X509GEneralName that parses structurally, but leniently should really go into awesn1
                //which should settle it. See https://github.com/a-sit-plus/awesn1/issues/37
                if (src.tag.isConstructed != expectedConstructed) {
                    throw Asn1Exception("GeneralName $type has an invalid tag: ${src.tag}")
                }

                return Registry.descriptorFor(type)
                    ?.let { catchingUnwrapped { it.fromAsn1Representation(src) }.getOrNull() }
                    ?: GenericX509GeneralName(type, src)
            }
        }
    }

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

    @ExperimentalPkiApi
    fun constrains(input: GeneralName?): ConstraintResult {
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
    fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName

}

internal fun GeneralName.requireX509(): GeneralName.X509Representable =
    this as? GeneralName.X509Representable
        ?: throw Asn1Exception("GeneralName has no X.509/DER representation")

private class GenericX509GeneralName(
    override val type: GeneralName.NameType,
    override val asn1Representation: Asn1Element,
) : GeneralName.X509Representable {

    override fun equals(other: Any?): Boolean =
        other is GeneralName.X509Representable &&
                type == other.type && asn1Representation == other.asn1Representation

    override fun hashCode(): Int = 31 * type.hashCode() + asn1Representation.hashCode()

    override fun toString(): String = "GeneralName(type=$type)"
    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName =
        throw IllegalArgumentException()
}
