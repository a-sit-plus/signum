package at.asitplus.signum.supreme

@RequiresOptIn(message = "Access to potentially hazardous platform-specific internals requires explicit opt-in. Specify @OptIn(HazardousMaterials::class). These accessors are unstable and may change without warning.")
/** This is an internal property. It is exposed if you know what you are doing. You very likely don't actually need it. */
annotation class HazardousMaterials


@RequiresOptIn(message = "Access to secret and private key material requires explicit opt-in. Specify @OptIn(SecretExposure::class). Make sure that you actually want to externalise a secret. Check yourself, before you really, really, wreck yourself!")
/** This guards a secret. Do not expose it lightly! */
annotation class SecretExposure

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CryptoOperationFailed(message: String) : CryptoException(message)
open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)
