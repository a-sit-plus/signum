package at.asitplus.signum.supreme

@RequiresOptIn
/** This is an internal property. It is exposed if you know what you are doing. You very likely don't actually need it. */
annotation class FootGunsAbound

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CryptoOperationFailed(message: String) : CryptoException(message)

open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

class UnlockFailed(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
