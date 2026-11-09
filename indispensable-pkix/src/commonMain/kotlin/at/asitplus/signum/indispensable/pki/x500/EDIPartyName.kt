package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName

/** RFC 5280 `ediPartyName` GeneralName CHOICE `[5]`. Carries the awesn1 [X509GeneralName.EdiParty] verbatim. */
class EDIPartyName private constructor(
    val ediParty: X509GeneralName.EdiParty,
    override val isValid: Boolean?,
) : AbstractGeneralName() {
    override val equalityValue get() = ediParty

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): EDIPartyName = EDIPartyName(ediParty, validate(this))

    override fun toString(): String = ediParty.toString()

    companion object {
        operator fun invoke(value: X509GeneralName.EdiParty): EDIPartyName = EDIPartyName(value, null)

        operator fun invoke(value: Asn1Sequence): EDIPartyName = invoke(X509GeneralName.EdiParty(value))

        /** Creates an instance with `isValid` determined by [validate]. */
        operator fun invoke(value: X509GeneralName.EdiParty, validate: (GeneralName) -> Boolean): EDIPartyName =
            EDIPartyName(value, validate(invoke(value)))

        val tag = X509GeneralName.Tags.ediPartyName
        internal fun fromAsn1Model(src: X509GeneralName): EDIPartyName {
            return EDIPartyName(src as X509GeneralName.EdiParty, null)
        }
    }
}
