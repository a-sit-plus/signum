package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.GeneralName

abstract class AbstractGeneralName : GeneralName {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    protected abstract val equalityValue: Any

    override fun equals(other: Any?): Boolean =
        other is AbstractGeneralName && this::class == other::class &&
                (equalityValue contentEqualsIfArray other.equalityValue)

    override fun hashCode(): Int = 31 * this::class.hashCode() + equalityValue.contentHashCodeIfArray()
}
