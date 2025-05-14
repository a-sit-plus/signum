package at.asitplus.signum

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CryptoOperationFailed(message: String) : CryptoException(message)
open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

sealed class CertificateException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CertificateChainValidatorException(message: String) : CertificateException(message)
open class KeyUsageException(message: String) : CertificateException(message)
open class CertificateValidityException(message: String) : CertificateException(message)
open class BasicConstraintsException(message: String) : CertificateException(message)
open class NameConstraintsException(message: String) : CertificateException(message)
open class CertificateExtensionException(message: String) : CertificateException(message)
