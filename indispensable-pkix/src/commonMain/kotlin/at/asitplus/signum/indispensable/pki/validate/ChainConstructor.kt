package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TrustAnchor

import at.asitplus.signum.indispensable.pki.CertificateChain

fun interface ChainConstructor {
    suspend fun buildChains(
        chain: CertificateChain,
        context: CertificateValidationContext
    ): Sequence<AnchoredCertificateChain>
}

class AnchoredCertificateChain(
    chain: CertificateChain,
    val trustAnchor: TrustAnchor
){

    /** The chain ordered from trust anchor to leaf (reverse of the conventional leaf-first order). */
    val validationPath : ValidationPath = ValidationPath(chain)

    /** The chain ordered from trust anchor to leaf (reverse of the conventional leaf-first order). */
    class ValidationPath(chain: CertificateChain): Sequence<Certificate> by chain.asReversed().asSequence()
}

