package at.asitplus.signum.supreme

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
class CryptoOperationFailed(message: String) : CryptoException(message)

class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)
