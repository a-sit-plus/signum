package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.GeneralName

/** Relation of this name to another name of the same form. */
enum class ConstraintResult { DIFF_TYPE, MATCH, NARROWS, WIDENS, SAME_TYPE }

abstract class AbstractGeneralName : GeneralName {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    protected abstract val equalityValue: Any

    @ExperimentalPkiApi
    open fun constrains(input: GeneralName?): ConstraintResult = fallbackConstrains(input)

    open fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName =
        throw UnsupportedOperationException("${this::class.simpleName} already implements validation")

    override fun equals(other: Any?): Boolean =
        other is AbstractGeneralName && this::class == other::class &&
                (equalityValue contentEqualsIfArray other.equalityValue)

    override fun hashCode(): Int = 31 * this::class.hashCode() + equalityValue.contentHashCodeIfArray()
}

@ExperimentalPkiApi
fun GeneralName.constrains(input: GeneralName?): ConstraintResult =
    if (this is AbstractGeneralName) constrains(input) else fallbackConstrains(input)

private fun GeneralName.fallbackConstrains(input: GeneralName?): ConstraintResult = when {
    input == null || this::class != input::class -> ConstraintResult.DIFF_TYPE
    isValid == null || input.isValid == null -> throw IllegalArgumentException(
        "${this::class.simpleName} requires explicit validation before checking name constraints"
    )
    isValid == false || input.isValid == false -> throw Asn1Exception("Invalid ${this::class.simpleName}")
    else -> throw UnsupportedOperationException("No constraint relation for ${this::class.simpleName}")
}
