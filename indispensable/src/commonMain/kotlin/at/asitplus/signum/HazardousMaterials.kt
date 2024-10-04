package at.asitplus.signum

@RequiresOptIn(message = "Access to potentially hazardous platform-specific internals requires explicit opt-in. Specify @OptIn(HazardousMaterials::class). These accessors are unstable and may change without warning.")
/** This is an internal property. It is exposed if you know what you are doing. You very likely don't actually need it. */
annotation class HazardousMaterials
