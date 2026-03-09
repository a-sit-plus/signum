package at.asitplus.signum.indispensable.pki

@Deprecated(
    "Moved to awesn1 raw crypto model.",
    ReplaceWith(
        "GeneralNames",
        "at.asitplus.awesn1.crypto.pki.GeneralNames"
    )
)
typealias AlternativeNames = at.asitplus.awesn1.crypto.pki.GeneralNames

@Deprecated(
    "Moved to awesn1 raw crypto model.",
    ReplaceWith(
        "GeneralNameImplicitTags",
        "at.asitplus.awesn1.crypto.pki.GeneralNameImplicitTags"
    )
)
typealias SubjectAltNameImplicitTags = at.asitplus.awesn1.crypto.pki.GeneralNameImplicitTags
