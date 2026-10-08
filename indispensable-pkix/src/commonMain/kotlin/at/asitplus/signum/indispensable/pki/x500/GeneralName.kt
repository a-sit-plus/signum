package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.Encodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.BaseX509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName.ConstraintResult
import at.asitplus.signum.indispensable.pki.tag
import at.asitplus.signum.indispensable.pki.asn1Representation as genericAsn1Representation
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer

abstract class AbstractX509GeneralName(
    model: X509GeneralName,
    sourceRepresentation: Pair<Encodable.Representation, Any>? = null,
) : BaseX509GeneralName(model, sourceRepresentation) {

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
        other is GeneralName &&
                 asn1Representation == other.genericAsn1Representation

    override fun hashCode(): Int = asn1Representation.hashCode()
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

private fun GeneralName.hasSameNameType(other: GeneralName): Boolean {
    val first = genericAsn1Representation
    val second = other.genericAsn1Representation
    return if (first != null && second != null) first::class == second::class else this::class == other::class
}

/**
 * Serializes a [GeneralName] by delegating to awesn1's [X509GeneralName] CHOICE serializer and routing
 * decode through the [GeneralName] registry (typed alternative when registered, generic
 * [BaseX509GeneralName] otherwise).
 */
internal object GeneralNameSerializer : KSerializer<GeneralName> by at.asitplus.signum.indispensable.GeneralNameAsn1Serializer

internal object GeneralNameListSerializer : KSerializer<List<GeneralName>> by ListSerializer(GeneralNameSerializer)

val AbstractX509GeneralName.asn1Representation: X509GeneralName
    get() = (this as BaseX509GeneralName).genericAsn1Representation

val AbstractX509GeneralName.tag: Asn1Element.Tag get() = asn1Representation.tag
