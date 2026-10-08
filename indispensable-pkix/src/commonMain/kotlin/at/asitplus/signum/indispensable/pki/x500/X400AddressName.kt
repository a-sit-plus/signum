package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName.Descriptor

/** RFC 5280 `x400Address` GeneralName CHOICE `[3]`. Carries the awesn1 [X509GeneralName.X400Address] verbatim. */
class X400AddressName private constructor(
    val x400Address: X509GeneralName.X400Address,
    override val isValid: Boolean?,
    sourceRepresentation: Pair<Encodable.Representation, Any>?,
) : AbstractX509GeneralName(x400Address, sourceRepresentation) {

    constructor(value: X509GeneralName.X400Address) : this(value, null, X509 to value)

    constructor(value: Asn1Sequence) : this(X509GeneralName.X400Address(value), null, null)

    /** Creates an instance with `isValid` determined by [validate]. */
    constructor(value: X509GeneralName.X400Address, validate: (GeneralName) -> Boolean) : this(value, validate(X400AddressName(value)), X509 to value)

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): X400AddressName = X400AddressName(x400Address, validate(this), sourceRepresentation)

    override fun toString(): String = x400Address.toString()

    companion object : Descriptor<X400AddressName>{
        override val tag = X509GeneralName.Tags.x400Address
        override fun fromAsn1Representation(src: X509GeneralName): X400AddressName {
            val source = X509 to src
            return X400AddressName(src as X509GeneralName.X400Address, null, source)
        }
    }
}
