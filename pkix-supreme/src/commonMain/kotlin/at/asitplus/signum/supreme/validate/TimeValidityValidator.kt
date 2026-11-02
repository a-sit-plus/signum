package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import at.asitplus.signum.indispensable.pki.checkValidityAt
import at.asitplus.signum.indispensable.pki.validationPath

/**
 * Validates that every certificate in the certification path is valid at the validation time.
 * The trust anchor is an input to path validation and is not itself part of the certification path.
 * Its own validity period is deliberately not checked: RFC 5280 §6.1 treats the anchor as trusted
 * input. Note that this means an expired anchor certificate in a trust store goes unnoticed here.
 */
class TimeValidityValidator: CertificateChainValidator {

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        for (cert in anchoredChain.chain.validationPath) {
            cert.checkValidityAt(context.date)
        }

        return emptyMap()
    }
}
