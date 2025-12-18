package at.asitplus.signum

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CryptoOperationFailed(message: String) : CryptoException(message)
open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

sealed class CertificateException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
class CertificateChainValidatorException(message: String) : CertificateException(message)
class KeyUsageException(message: String) : CertificateException(message)
class ExtendedKeyUsageException(message: String) : CertificateException(message)
class CertificateValidityException(message: String) : CertificateException(message)
class BasicConstraintsException(message: String) : CertificateException(message)
class NameConstraintsException(message: String) : CertificateException(message)
class CertificatePolicyException(message: String) : CertificateException(message)
