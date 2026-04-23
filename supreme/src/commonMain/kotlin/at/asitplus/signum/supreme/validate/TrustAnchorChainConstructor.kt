package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.root

/**
 * Builds candidate certificate chains by attaching matching trust anchors.
 *
 * The input chain is assumed to be fixed. For each trust anchor that can
 * issue the root certificate, a candidate chain is produced.
 */
class TrustAnchorChainConstructor : ChainConstructor {

    @ExperimentalPkiApi
    override suspend fun buildChains(
        chain: CertificateChain,
        context: CertificateValidationContext
    ): Sequence<AnchoredCertificateChain> {
        val results = mutableListOf<AnchoredCertificateChain>()
        val processingChain = if (context.allowIncludedTrustAnchor && context.trustAnchors.any {
                it.matchesCertificate(chain.root)
            }) chain.dropLast(1) else chain

        for (anchor in context.trustAnchors) {

            if (!anchor.isIssuerOf(chain.root)) continue

            results += AnchoredCertificateChain(
                chain = processingChain,
                trustAnchor = anchor
            )
        }

        return results.asSequence()
    }
}