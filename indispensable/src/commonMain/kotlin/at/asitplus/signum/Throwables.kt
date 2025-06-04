package at.asitplus.signum

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CryptoOperationFailed(message: String) : CryptoException(message)
open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

sealed class CertificateException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
sealed class CertificateChainValidatorException(message: String) : CertificateException(message)
sealed class KeyUsageException(message: String) : CertificateException(message)
sealed class CertificateValidityException(message: String) : CertificateException(message)
sealed class BasicConstraintsException(message: String) : CertificateException(message)
sealed class NameConstraintsException(message: String) : CertificateException(message)
sealed class CertificatePolicyException(message: String) : CertificateException(message)
