package at.asitplus.signum.supreme

@RequiresOptIn(message = "Access to potentially hazardous platform-specific internals requires explicit opt-in. Specify @OptIn(HazardousMaterials::class). These accessors are unstable and may change without warning.")
/** This is an internal property. It is exposed if you know what you are doing. You very likely don't actually need it. */
annotation class HazardousMaterials

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CryptoOperationFailed(message: String) : CryptoException(message)

open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

class UnlockFailed(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
