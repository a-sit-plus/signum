package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CRLCertRevokedException
import at.asitplus.signum.CRLRevocationException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.OCSPCertRevokedException
import at.asitplus.signum.OCSPRevocationException
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.X509Certificate

class RevocationValidator(
    private val ocspValidator: OCSPRevocationValidator = OCSPRevocationValidator(),
    private val crlValidator: CRLRevocationValidator = CRLRevocationValidator()
) : CertificateChainValidator {

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        return when (context.revocationMode) {

            RevocationMode.PREFER_OCSP -> {
                try {
                    ocspValidator.validate(anchoredChain, context)
                } catch (e: OCSPCertRevokedException) {
                    throw e
                } catch (_: OCSPRevocationException) {
                    crlValidator.validate(anchoredChain, context)
                }
            }
            RevocationMode.PREFER_CRL -> {
                try {
                    crlValidator.validate(anchoredChain, context)
                } catch (e: CRLCertRevokedException) {
                    throw e
                } catch (_: CRLRevocationException) {
                    ocspValidator.validate(anchoredChain, context)
                }
            }
            RevocationMode.ONLY_OCSP -> {
                ocspValidator.validate(anchoredChain, context)
            }
            RevocationMode.ONLY_CRL -> {
                crlValidator.validate(anchoredChain, context)
            }
        }
    }
}

enum class RevocationMode {
    PREFER_OCSP,
    PREFER_CRL,
    ONLY_OCSP,
    ONLY_CRL
}