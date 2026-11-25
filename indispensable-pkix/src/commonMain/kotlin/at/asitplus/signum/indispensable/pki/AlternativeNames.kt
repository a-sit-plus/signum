package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.issuerAltName_2_5_29_18
import at.asitplus.awesn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.SourceRepresentationStorage

data class SubjectAlternativeName(
    override val generalNames: List<GeneralName>,
    override val critical: Boolean = false,
) : AlternativeNamesExtension {
    override val oid get() = KnownOIDs.subjectAltName_2_5_29_17
    override val sourceRepresentation = SourceRepresentationStorage()
}

data class IssuerAlternativeName(
    override val generalNames: List<GeneralName>,
    override val critical: Boolean = false,
) : AlternativeNamesExtension {
    override val oid get() = KnownOIDs.issuerAltName_2_5_29_18
    override val sourceRepresentation = SourceRepresentationStorage()
}
