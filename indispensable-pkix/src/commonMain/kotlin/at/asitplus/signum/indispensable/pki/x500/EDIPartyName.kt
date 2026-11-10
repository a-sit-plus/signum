package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.GeneralName

/** RFC 5280 `ediPartyName`: a party name and its optional name assigner. */
data class EDIPartyName(
    val partyName: String,
    val nameAssigner: String? = null,
) : GeneralName {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()

    init {
        require(partyName.isNotEmpty()) { "EDI party name cannot be empty" }
        require(nameAssigner == null || nameAssigner.isNotEmpty()) { "EDI name assigner cannot be empty" }
    }

    companion object {
        operator fun invoke(value: X509GeneralName.EdiParty): EDIPartyName = GeneralName.fromAsn1(value) as EDIPartyName

        operator fun invoke(value: Asn1Sequence): EDIPartyName = invoke(X509GeneralName.EdiParty(value))

        val tag = X509GeneralName.Tags.ediPartyName
    }
}
