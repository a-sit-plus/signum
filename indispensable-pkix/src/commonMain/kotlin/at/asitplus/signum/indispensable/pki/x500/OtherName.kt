package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName

/** RFC 5280 `otherName` GeneralName CHOICE `[0]`. Carries the awesn1 [X509GeneralName.Other] verbatim. */
class OtherName private constructor(
    val other: X509GeneralName.Other,
    override val isValid: Boolean?,
) : AbstractGeneralName() {
    override val equalityValue get() = other

    constructor(value: X509GeneralName.Other) : this(value, null)

    /** Creates an instance with `isValid` determined by [validate]. */
    constructor(value: X509GeneralName.Other, validate: (GeneralName) -> Boolean) : this(value, validate(OtherName(value)))

    /** The open, OID-discriminated `otherName` payload. */
    val value: X509GeneralName.Other.SemanticValue get() = other.value

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): OtherName = OtherName(other, validate(this))

    override fun toString(): String = other.toString()

    companion object {
        val tag = X509GeneralName.Tags.otherName
        internal fun fromAsn1Model(src: X509GeneralName): OtherName {
            return OtherName(src as X509GeneralName.Other, null)
        }
    }
}
