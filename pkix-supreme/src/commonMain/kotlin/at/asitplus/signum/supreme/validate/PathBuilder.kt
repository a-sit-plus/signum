package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.TrustAnchor

/**
 * Builds candidate certification paths for a given end-entity-first [CertificateChain]
 * using trust anchors and any other resources exposed via [CertificateValidationContext]
 */
fun interface PathBuilder {

    /**
     * Produces candidate anchored chains to attempt validation against.
     *
     * Implementations must not throw merely because no candidates were found —
     * return an empty list in that case.
     */
    suspend fun CertificateChain.buildCandidates(
        context: CertificateValidationContext
    ): List<AnchoredCertificateChain>

    companion object {
        /**
         * Minimal builder matches configured trust anchors directly against the
         * supplied chain. No network fetching or cross-certification.
         */
        val Default: PathBuilder = TrustAnchorPathBuilder()
    }
}

data class AnchoredCertificateChain(
    val chain: CertificateChain,
    val trustAnchor: TrustAnchor
)