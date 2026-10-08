package at.asitplus.signum.indispensable.pki

/**
 * Marks elements of the certificate validation (PKI) API as experimental and subject to change.
 * This includes all certificate path validation logic, constraint processing (e.g., NameConstraints),
 * and any general name comparison or restriction checks.
 *
 * Lives in `indispensable-pkix`, alongside typed name constraints.
 * [at.asitplus.signum.indispensable.pki.x500.AbstractX509GeneralName]'s constraint API is gated by it.
 */
@RequiresOptIn(
    message = "This API is part of the experimental certificate validation feature. " +
            "It may not yet handle everything according to spec, could contain vulnerabilities, may change without notice, or eat your cat. " +
            "Specify @OptIn(ExperimentalPkiApi::class)"
)
annotation class ExperimentalPkiApi(val message: String = "")
