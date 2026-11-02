package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName.ConstraintResult
import at.asitplus.signum.indispensable.pki.GeneralName.X509Representable
import at.asitplus.signum.indispensable.pki.tag
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

abstract class AbstractX509GeneralName(
    final override val asn1Representation: X509GeneralName,
) : GeneralName.X509Representable {

    final override val tag: Asn1Element.Tag get() = asn1Representation.tag

    /**
     * Constraint relation of this name against [input]. The base implementation only distinguishes
     * name-type equality; typed variants override it with their RFC 5280 narrows/widens/match logic.
     */
    @ExperimentalPkiApi
    open fun constrains(input: GeneralName?): ConstraintResult = fallbackConstrains(input)

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName =
        throw UnsupportedOperationException(
            "${this::class.simpleName} implements validation itself; createValidatedCopy is only for " +
                    "variants that do not (isValid == null)."
        )

    override fun equals(other: Any?): Boolean =
        other is GeneralName.X509Representable &&
                 asn1Representation == other.asn1Representation

    override fun hashCode(): Int = 31 + asn1Representation.hashCode()
}

/**
 * Dispatches to the polymorphic [AbstractX509GeneralName.constrains] member (so typed variants' overrides
 * win) for X.509-backed names, falling back to [fallbackConstrains] for anything else.
 */
@ExperimentalPkiApi
fun GeneralName.constrains(input: GeneralName?): ConstraintResult =
    if (this is AbstractX509GeneralName) constrains(input) else fallbackConstrains(input)

private fun GeneralName.fallbackConstrains(input: GeneralName?): ConstraintResult {
    when {
        input == null || !hasSameNameType(input) -> return ConstraintResult.DIFF_TYPE

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

private fun GeneralName.hasSameNameType(other: GeneralName): Boolean =
    if (this is X509Representable && other is X509Representable) {
        asn1Representation::class == other.asn1Representation::class
    } else {
        this::class == other::class
    }

/**
 * Serializes a [GeneralName] by delegating to awesn1's [X509GeneralName] CHOICE serializer and routing
 * decode through the [GeneralName.X509Representable] registry (typed alternative when registered, generic
 * [at.asitplus.signum.indispensable.pki.BaseX509GeneralName] otherwise).
 */
internal object GeneralNameSerializer : KSerializer<GeneralName> {
    private val delegate = X509GeneralName.serializer()
    override val descriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: GeneralName) =
        encoder.encodeSerializableValue(
            delegate,
            (value as? GeneralName.X509Representable
                ?: throw Asn1Exception("GeneralName has no X.509/DER representation")).asn1Representation,
        )

    override fun deserialize(decoder: Decoder): GeneralName =
        GeneralName.X509Representable.fromAsn1Representation(decoder.decodeSerializableValue(delegate))
}

internal object GeneralNameListSerializer : KSerializer<List<GeneralName>> by ListSerializer(GeneralNameSerializer)
