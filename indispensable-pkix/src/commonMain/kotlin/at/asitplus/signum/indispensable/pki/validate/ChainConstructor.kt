package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.indispensable.pki.TrustAnchor

import at.asitplus.signum.indispensable.pki.CertificateChain

fun interface ChainConstructor {
    suspend fun buildChains(
        chain: CertificateChain,
        context: CertificateValidationContext
    ): Sequence<AnchoredCertificateChain>
}

data class AnchoredCertificateChain(
    val chain: CertificateChain,
    val trustAnchor: TrustAnchor
)