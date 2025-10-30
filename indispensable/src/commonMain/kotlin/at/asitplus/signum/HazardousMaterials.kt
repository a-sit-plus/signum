package at.asitplus.signum

@RequiresOptIn(message = "Access to potentially hazardous cryptographic functions requires explicit opt-in. Specify @OptIn(HazardousMaterials::class). These accessors are unstable and may change without warning.")
/** This is dangerous. It is exposed if you know what you are doing. You very likely don't actually need it. */
@Repeatable
annotation class HazardousMaterials(val message: String="")

@RequiresOptIn(message = "This API is part of the experimental certificate validation feature. " +
        "It may not yet handle everything according to spec, could contain vulnerabilities, may change without notice, or eat your cat. " +
        "Specify @OptIn(ExperimentalPkiApi::class)")
/**
 * Marks elements of the certificate validation (PKI) api as experimental and subject to change.
 * This includes all certificate path validation logic, constraint processing (e.g., NameConstraints),
 * and any general name comparison or restriction checks.
 */
annotation class ExperimentalPkiApi(val message: String = "")