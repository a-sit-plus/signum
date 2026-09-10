package at.asitplus.signum

open class CryptoOperationFailed(message: String) : RuntimeException(message)
open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) :
    UnsupportedOperationException(message, cause)

