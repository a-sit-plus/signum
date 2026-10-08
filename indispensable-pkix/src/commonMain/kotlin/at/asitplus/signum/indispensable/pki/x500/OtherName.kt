package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName.Descriptor

/** RFC 5280 `otherName` GeneralName CHOICE `[0]`. Carries the awesn1 [X509GeneralName.Other] verbatim. */
class OtherName private constructor(
    val other: X509GeneralName.Other,
    override val isValid: Boolean?,
    sourceRepresentation: Pair<Encodable.Representation, Any>?,
) : AbstractX509GeneralName(other, sourceRepresentation) {

    constructor(value: X509GeneralName.Other) : this(value, null, X509 to value)

    /** Creates an instance with `isValid` determined by [validate]. */
    constructor(value: X509GeneralName.Other, validate: (GeneralName) -> Boolean) : this(value, validate(OtherName(value)), X509 to value)

    /** The open, OID-discriminated `otherName` payload. */
    val value: X509GeneralName.Other.SemanticValue get() = other.value

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): OtherName = OtherName(other, validate(this), sourceRepresentation)

    override fun toString(): String = other.toString()

    companion object : Descriptor<OtherName>{
        override val tag = X509GeneralName.Tags.otherName
        override fun fromAsn1Representation(src: X509GeneralName): OtherName {
            val source = X509 to src
            return OtherName(src as X509GeneralName.Other, null, source)
        }
    }
}
