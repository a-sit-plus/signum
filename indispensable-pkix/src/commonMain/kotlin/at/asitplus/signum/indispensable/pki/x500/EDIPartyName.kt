package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName.X509Representable.Descriptor

/** RFC 5280 `ediPartyName` GeneralName CHOICE `[5]`. Carries the awesn1 [X509GeneralName.EdiParty] verbatim. */
class EDIPartyName private constructor(
    val ediParty: X509GeneralName.EdiParty,
    override val isValid: Boolean?,
) : AbstractX509GeneralName(ediParty) {

    constructor(value: X509GeneralName.EdiParty) : this(value, null)

    constructor(value: Asn1Sequence) : this(X509GeneralName.EdiParty(value))

    /** Creates an instance with `isValid` determined by [validate]. */
    constructor(value: X509GeneralName.EdiParty, validate: (GeneralName) -> Boolean) : this(value, validate(EDIPartyName(value)))

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): EDIPartyName = EDIPartyName(ediParty, validate)

    override fun toString(): String = ediParty.toString()

    companion object : Descriptor {
        override val tag = X509GeneralName.Tags.ediPartyName
        override fun fromAsn1Representation(src: X509GeneralName): EDIPartyName = EDIPartyName(src as X509GeneralName.EdiParty)
    }
}
