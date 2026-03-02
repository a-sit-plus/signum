package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlin.coroutines.cancellation.CancellationException

interface CertificateValidator : CertificateChainValidator {

    /**
     * Performs certificate validation for the given certificate
     * Every validator adds checked critical extensions
     *
     * @throws CertificateException If the certificate fails validation according to the rules implemented by this validator
     * @throws CancellationException
     * @throws Throwable For multiplatform safety (e.g., Kotlin/Native to Swift), this allows catching all exceptions without crashing the application.
     */
    @ExperimentalPkiApi
    @Throws(Throwable::class)
    suspend fun check(currCert: X509Certificate) : Set<ObjectIdentifier>

    @OptIn(ExperimentalPkiApi::class)
    override suspend fun validate(
        chain: CertificateChain,
        context: CertificateValidationContext,
        checkedCriticalExtensions: MutableMap<X509Certificate, MutableSet<ObjectIdentifier>>
    ) {
        chain.forEach {
            checkedCriticalExtensions
                .getOrPut(it) { mutableSetOf() }
                .addAll(check(it))
        }
    }
}