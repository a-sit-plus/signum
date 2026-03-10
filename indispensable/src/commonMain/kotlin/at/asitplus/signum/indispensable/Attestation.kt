package at.asitplus.signum.indispensable

import kotlinx.serialization.json.Json

@Deprecated(
    "Moved to at.asitplus.signum.indispensable.attestation.",
    ReplaceWith("Attestation", "at.asitplus.signum.indispensable.attestation.Attestation")
)
typealias Attestation = at.asitplus.signum.indispensable.attestation.Attestation

@Deprecated(
    "Moved to at.asitplus.signum.indispensable.attestation.",
    ReplaceWith("SelfAttestation", "at.asitplus.signum.indispensable.attestation.SelfAttestation")
)
typealias SelfAttestation = at.asitplus.signum.indispensable.attestation.SelfAttestation

@Deprecated(
    "Moved to at.asitplus.signum.indispensable.attestation.",
    ReplaceWith(
        "AndroidKeystoreAttestation",
        "at.asitplus.signum.indispensable.attestation.AndroidKeystoreAttestation"
    )
)
typealias AndroidKeystoreAttestation = at.asitplus.signum.indispensable.attestation.AndroidKeystoreAttestation

@Deprecated(
    "Moved to at.asitplus.signum.indispensable.attestation.",
    ReplaceWith(
        "IosHomebrewAttestation",
        "at.asitplus.signum.indispensable.attestation.IosHomebrewAttestation"
    )
)
typealias IosHomebrewAttestation = at.asitplus.signum.indispensable.attestation.IosHomebrewAttestation

@Deprecated(
    "Moved to at.asitplus.signum.indispensable.attestation.",
    ReplaceWith(
        "IosHomebrewAttestation.ClientData",
        "at.asitplus.signum.indispensable.attestation.IosHomebrewAttestation"
    )
)
typealias IosHomebrewAttestationClientData = at.asitplus.signum.indispensable.attestation.IosHomebrewAttestation.ClientData

@Deprecated(
    "Moved to at.asitplus.signum.indispensable.attestation.",
    ReplaceWith("StrictJson", "at.asitplus.signum.indispensable.attestation.StrictJson")
)
val StrictJson: Json
    get() = at.asitplus.signum.indispensable.attestation.StrictJson

@Deprecated(
    "Moved to at.asitplus.signum.indispensable.attestation.",
    ReplaceWith("jsonEncoded", "at.asitplus.signum.indispensable.attestation.jsonEncoded")
)
val Attestation.jsonEncoded: String
    get() = kotlinx.serialization.json.Json.encodeToString(this)
