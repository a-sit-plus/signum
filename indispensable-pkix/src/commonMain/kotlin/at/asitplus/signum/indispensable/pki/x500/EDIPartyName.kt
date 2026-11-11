package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import kotlinx.serialization.Serializable
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

    /** ASN.1 schema from [RFC 5280, Section 4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6). */
    @Serializable
    internal data class Asn1Representation(
        @Asn1Tag(0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
        val nameAssigner: ExplicitlyTagged<Asn1String>? = null,
        @Asn1Tag(1u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
        val partyName: ExplicitlyTagged<Asn1String>,
    ) {
        init {
            require(listOfNotNull(nameAssigner?.value, partyName.value).all {
                (it is Asn1String.Teletex || it is Asn1String.Printable || it is Asn1String.Universal ||
                        it is Asn1String.UTF8 || it is Asn1String.BMP) && it.isValid != false
            }) { "EDI names must contain valid DirectoryStrings" }
        }
    }

    companion object {
        operator fun invoke(value: X509GeneralName.EdiParty): EDIPartyName = GeneralName.fromAsn1(value) as EDIPartyName

        operator fun invoke(value: Asn1Sequence): EDIPartyName = invoke(X509GeneralName.EdiParty(value))

        val tag = X509GeneralName.Tags.ediPartyName
    }
}
