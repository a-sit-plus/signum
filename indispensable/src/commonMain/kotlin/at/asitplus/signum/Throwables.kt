package at.asitplus.signum

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CryptoOperationFailed(message: String) : CryptoException(message)
open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

open class CertificateException(
    message: String? = null,
    cause: Throwable? = null,
    var certificateIndex: Int? = null
) : Throwable(message, cause) {
    override val message: String?
        get() = super.message?.let { msg ->
            if (certificateIndex != null) "$msg (certificate index $certificateIndex)" else msg
        } ?: if (certificateIndex != null) "Certificate error at index $certificateIndex" else null
}
class CertificateChainValidatorException(message: String) : CertificateException(message)
sealed class CertificateValidityException(message: String) : CertificateException(message)
class CertificateSerialNumberException(message: String) : CertificateValidityException(message)
class SanNotCriticalWithEmptySubjectException(message: String) : CertificateValidityException(message)
class KeyUsageException(message: String) : CertificateException(message)
class ExtendedKeyUsageException(message: String) : CertificateException(message)
sealed class CertificateTimeValidityException(message: String) : CertificateException(message)
class CertificateNotYetValidException(message: String) : CertificateTimeValidityException(message)
class CertificateExpiredException(message: String) : CertificateTimeValidityException(message)
class InvalidCertificateValidityPeriodException(message: String) : CertificateTimeValidityException(message)
sealed class BasicConstraintsException(message: String) : CertificateException(message)
class MissingBasicConstraintsException(message: String) : BasicConstraintsException(message)
class NonCriticalBasicConstraintsException(message: String) : BasicConstraintsException(message)
class MissingCaFlagException(message: String) : BasicConstraintsException(message)
class PathLenConstraintViolationException(message: String) : BasicConstraintsException(message)

class NameConstraintsException(message: String) : CertificateException(message)
class GeneralNameException(message: String) : CertificateException(message)
class CertificatePolicyException(message: String) : CertificateException(message)
sealed class KeyIdentifierException(message: String) : CertificateException(message)
class MissingSubjectKeyIdentifierException(message: String) : KeyIdentifierException(message)
class CriticalSubjectKeyIdentifierException(message: String) : KeyIdentifierException(message)
class MissingAuthorityKeyIdentifierException(message: String) : KeyIdentifierException(message)
class CriticalAuthorityKeyIdentifierException(message: String) : KeyIdentifierException(message)

sealed class RevocationException(message: String) : CertificateException(message)
open class CRLRevocationException(message: String) : RevocationException(message)
class CRLExpiredException(message: String) : CRLRevocationException(message)
class CRLNotYetValidException(message: String) : CRLRevocationException(message)
class CrlSignatureException(message: String) : CRLRevocationException(message)
class CrlIssuerMismatchException(message: String) : CRLRevocationException(message)
class CrlMissingPublicKeyException(message: String) : CRLRevocationException(message)
class CrlInvalidSignatureAlgorithmException(message: String) : CRLRevocationException(message)
class CrlDistributionPointMismatchException (message: String) : CRLRevocationException(message)
class MissingCrlDistributionPointsException (message: String) : CRLRevocationException(message)
class CrlScopeViolationException (message: String) : CRLRevocationException(message)

open class OCSPRevocationException(message: String) : RevocationException(message)
class OCSPExpiredException(message: String) : OCSPRevocationException(message)
class OCSPNotYetValidException(message: String) : OCSPRevocationException(message)
class OCSPMissingBasicResponseException(message: String) : OCSPRevocationException(message)
class OCSPStatusException(message: String) : OCSPRevocationException(message)

class OCSPResponseSignatureException(message: String) : OCSPRevocationException(message)
class OCSPResponderMismatchException(message: String) : OCSPRevocationException(message)
class OCSPDelegatedResponderException(message: String) : OCSPRevocationException(message)
class OCSPUnauthorizedResponderException(message: String) : OCSPRevocationException(message)

class OCSPUnsupportedCriticalExtensionException(message: String) : OCSPRevocationException(message)
class OCSPUnsupportedVersionException(message: String) : OCSPRevocationException(message)

class OCSPCertRevokedException(message: String) : OCSPRevocationException(message)
class OCSPCertUnknownException(message: String) : OCSPRevocationException(message)

class OCSPNoMatchingResponseException(message: String) : OCSPRevocationException(message)
class OCSPMissingAiaExtensionException(message: String) : OCSPRevocationException(message)
class OCSPMissingOcspUrlException(message: String) : OCSPRevocationException(message)

