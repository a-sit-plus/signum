package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.root

/**
 * A [PathBuilder] that constructs all candidate certification paths by
 * matching certificate `subject` names against `issuer` names.
 *
 * It recursively builds paths starting from the top of the input chain using
 * the pool of intermediate certificates provided in [intermediatePool] (as well as
 * any available in the [CertificateValidationContext]).
 *
 * @param intermediatePool Pool of untrusted/intermediate certificates available for path building.
 * @param maxPathLength Maximum allowed certificates in a single chain to prevent runaway search.
 */
class SubjectNamePathBuilder(
    private val intermediatePool: Collection<Certificate> = emptyList(),
    private val maxPathLength: Int = 10
) : PathBuilder {

    @OptIn(ExperimentalPkiApi::class)
    override suspend fun CertificateChain.buildCandidates(
        context: CertificateValidationContext
    ): List<AnchoredCertificateChain> {
        val candidateAnchors = context.trustAnchors

        // Index unique intermediates by subject name
        val intermediatesBySubject: Map<String, List<Certificate>> =
            (intermediatePool.toSet() + context.intermediateCertificates.toSet())
                .groupBy { it.tbsCertificate.subjectName.canonicalForMatching() }

        val results = mutableSetOf<AnchoredCertificateChain>()

        suspend fun searchPaths(
            currentChain: CertificateChain,
            visited: Set<Certificate>
        ) {
            if (currentChain.size >= maxPathLength) return

            val currentRoot = currentChain.root

            // Try anchoring the current chain against candidate trust anchors
            for (anchor in candidateAnchors) {
                val anchorCert = anchor.cert

                if (anchor.isIssuerOf(currentRoot)) {
                    results.add(
                        AnchoredCertificateChain(
                            chain = currentChain,
                            trustAnchor = anchor
                        )
                    )
                } else if (
                    context.allowIncludedTrustAnchor &&
                    anchorCert != null &&
                    anchorCert == currentRoot &&
                    currentChain.size > 1
                ) {
                    results.add(
                        AnchoredCertificateChain(
                            chain = currentChain.dropLast(1),
                            trustAnchor = anchor
                        )
                    )
                }
            }

            // Find matching intermediate certificates where candidate.subject == currentRoot.issuer
            val matchingIntermediates = intermediatesBySubject[currentRoot.tbsCertificate.issuerName.canonicalForMatching()]
                .orEmpty()
                .filter { it !in visited }

            // Extend chain and recurse
            for (nextIntermediate in matchingIntermediates) {
                val extendedChain = currentChain + nextIntermediate
                searchPaths(
                    currentChain = extendedChain,
                    visited = visited + nextIntermediate
                )
            }
        }

        searchPaths(
            currentChain = this,
            visited = emptySet()
        )

        return results.toList()
    }
}