package at.asitplus.signum

@RequiresOptIn(message = "Access to potentially hazardous cryptographic functions requires explicit opt-in. Specify @OptIn(HazardousMaterials::class). These accessors are unstable and may change without warning.")
/** This is dangerous. It is exposed if you know what you are doing. You very likely don't actually need it. */
@Repeatable
annotation class HazardousMaterials(val message: String="")

@RequiresOptIn(message = "This is internal to Signum and only publicly visible for language reasons. There are no guarantees as to its stability.")
@Repeatable
annotation class SignumInternals(val message: String="")
