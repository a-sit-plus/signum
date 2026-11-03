package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName.Descriptor

/** RFC 5280 `ediPartyName` GeneralName CHOICE `[5]`. Carries the awesn1 [X509GeneralName.EdiParty] verbatim. */
class EDIPartyName private constructor(
    val ediParty: X509GeneralName.EdiParty,
    override val isValid: Boolean?,
    sourceRepresentation: Pair<Encodable.Representation, Any>?,
) : AbstractX509GeneralName(ediParty, sourceRepresentation) {

    constructor(value: X509GeneralName.EdiParty) : this(value, null, X509 to value)

    constructor(value: Asn1Sequence) : this(X509GeneralName.EdiParty(value), null, null)

    /** Creates an instance with `isValid` determined by [validate]. */
    constructor(value: X509GeneralName.EdiParty, validate: (GeneralName) -> Boolean) : this(value, validate(EDIPartyName(value)), X509 to value)

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): EDIPartyName = EDIPartyName(ediParty, validate(this), sourceRepresentation)

    override fun toString(): String = ediParty.toString()

    companion object : Descriptor<EDIPartyName>{
        override val tag = X509GeneralName.Tags.ediPartyName
        override fun fromAsn1Representation(src: X509GeneralName): EDIPartyName {
            val source = X509 to src
            return EDIPartyName(src as X509GeneralName.EdiParty, null, source)
        }
    }
}
