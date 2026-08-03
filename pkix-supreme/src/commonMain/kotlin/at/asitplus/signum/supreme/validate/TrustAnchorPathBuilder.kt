package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.root

/**
 * Default, minimal certification path builder.
 *
 * Matches trust anchors available in a [CertificateValidationContext] against the
 * root certificate of a supplied [CertificateChain].
 */
class TrustAnchorPathBuilder : PathBuilder {

    @OptIn(ExperimentalPkiApi::class)
    override suspend fun CertificateChain.buildCandidates(
        context: CertificateValidationContext
    ): List<AnchoredCertificateChain> {
        val processingChain = if (
            context.allowIncludedTrustAnchor &&
            context.trustAnchors.any { it.matchesCertificate(root) }
        ) {
            dropLast(1)
        } else {
            this
        }

        return context.trustAnchors
            .filter { it.isIssuerOf(root) }
            .map { anchor ->
                AnchoredCertificateChain(
                    chain = processingChain,
                    trustAnchor = anchor
                )
            }
    }
}