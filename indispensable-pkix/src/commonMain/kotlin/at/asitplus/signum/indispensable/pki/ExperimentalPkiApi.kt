package at.asitplus.signum.indispensable.pki

/**
 * Marks elements of the certificate validation (PKI) API as experimental and subject to change.
 * This includes all certificate path validation logic, constraint processing (e.g., NameConstraints),
 * and any general name comparison or restriction checks.
 *
 * Lives in the lean `indispensable` core (not `indispensable-pkix`) because core types such as
 * [at.asitplus.signum.indispensable.pki.x500.GeneralName]'s constraint API are gated by it, and core
 * cannot depend on `indispensable-pkix`.
 */
@RequiresOptIn(
    message = "This API is part of the experimental certificate validation feature. " +
            "It may not yet handle everything according to spec, could contain vulnerabilities, may change without notice, or eat your cat. " +
            "Specify @OptIn(ExperimentalPkiApi::class)"
)
annotation class ExperimentalPkiApi(val message: String = "")
