package at.asitplus.signum.supreme.dsl

/** Tri-state setting for enabling a given feature.
 * @see REQUIRED
 * @see PREFERRED
 * @see DISCOURAGED
 */
sealed interface FeaturePreference
/** Marks this feature as non-negotiable and absolutely required.
   If the feature is not available on the current platform, the operation may fail. */
object REQUIRED : FeaturePreference
/** Marks this feature as preferred.
   If the feature is available on the current platform and with the specified configuration, it will be used.
   If not, it will silently not be used. The effective state might be determined from the output. */
object PREFERRED : FeaturePreference
/** Marks this feature as discouraged.
   If it is possible to complete the operation without using the feature, this will be done.
   The feature will only be used if its use is required to allow the operation to succeed. */
object DISCOURAGED : FeaturePreference
