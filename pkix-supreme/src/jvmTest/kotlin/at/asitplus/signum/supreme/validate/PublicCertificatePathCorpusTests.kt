package at.asitplus.signum.supreme.validate

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.SignumPkix
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * Offline upstream acceptance/rejection vectors, pinned and attributed in corpora/public-paths.json.
 * Source expectations are not inverted to match Signum. The importer records policy exclusions.
 * These are path-validation/interoperability tests, not claims of equivalent TLS/trust-store policy.
 *
 * Go supplies explicit root-to-leaf levels of certificate alternatives. The exporter enumerates
 * those supplied candidate paths; this tests validation of every candidate, not Signum path discovery.
 * No test-generated path can pass solely because the harness picked an invalid alternative.
 */
@OptIn(ExperimentalPkiApi::class)
val PublicCertificatePathCorpusTests by matrixSuite {
    SignumPkix.install()
    val corpus = json.decodeFromString<PublicPathCorpus>(resourceText("corpora/public-paths.json"))
    require(corpus.cases.map { it.source to it.id }.distinct().size == corpus.cases.size)
    require(corpus.cases.all { case ->
        case.anchors.isNotEmpty() && case.paths.isNotEmpty() && case.paths.all { it.isNotEmpty() } &&
                (case.expectedValid || case.expectedValidators.isNotEmpty()) &&
                (case.anchors + case.paths.flatten()).all { it in corpus.certificates }
    }) { "Incomplete corpus fixture or unspecified rejection reason" }

    corpus.cases.asData(nameFn = {
        "${if (it.expectedValid) "ACCEPT" else "REJECT"} ${it.source}: ${it.id}"
    }) test { case ->
        withClue("${case.sourceUrl}\nUpstream: ${case.description}") {
            // Catch only input-decoding errors, outside assertions and validator execution. A failed
            // assertion, unsupported crypto operation, or arbitrary exception is never a rejection pass.
            val decoded = try {
                (case.anchors + case.paths.flatten()).distinct().associateWith { ref ->
                    Certificate.decodeFromPem(corpus.certificates.getValue(ref))
                }
            } catch (error: Asn1Exception) {
                withClue("Decoding-stage rejection: $error") {
                    case.expectedValid shouldBe false
                    case.allowDecodeRejection shouldBe true
                }
                return@test
            } catch (error: IllegalArgumentException) {
                withClue("Decoding-stage rejection: $error") {
                    case.expectedValid shouldBe false
                    case.allowDecodeRejection shouldBe true
                }
                return@test
            } catch (error: UnsupportedCryptoException) {
                // BoringSSL's invalid-SPKI vector deliberately uses unknown public-key OID 1.2.3.4.
                // Inability to decode THAT input is its expected rejection, not a false acceptance.
                // Unsupported crypto for ordinary/positive vectors must still fail the test.
                if (!case.allowUnsupportedCryptoAtDecode) throw error
                case.expectedValid shouldBe false
                return@test
            }
            val results = mutableListOf<CertificateValidationResult>()
            for (path in case.paths) for (anchorRef in case.anchors) {
                val anchor = TrustAnchor.Certificate(decoded.getValue(anchorRef))
                results += AnchoredCertificateChain(path.map(decoded::getValue), anchor).validate(
                    ValidatorFactory.RFC5280,
                    CertificateValidationContext(
                        date = Instant.parse(case.validationTime),
                        trustAnchors = setOf(anchor),
                        allowIncludedTrustAnchor = false,
                        expectedEku = case.expectedEku.map(::ObjectIdentifier).toSet(),
                        initialPolicies = case.initialPolicies.map(::ObjectIdentifier).toSet(),
                        explicitPolicyRequired = case.explicitPolicyRequired,
                        anyPolicyInhibited = case.anyPolicyInhibited,
                        policyMappingInhibited = case.policyMappingInhibited,
                    ),
                )
            }
            val diagnostics = results.joinToString("\n") { result ->
                when (result) {
                    is CertificateValidationResult.Failure -> result.validatorFailures.joinToString { "${it.validatorName}: ${it.errorMessage}" }
                    is CertificateValidationResult.Success -> "ACCEPTED"
                    is CertificateValidationResult.BuildPathFailure -> "Unexpected BuildPathFailure"
                }
            }
            withClue(diagnostics) {
                results.any { it.isValid } shouldBe case.expectedValid
                if (!case.expectedValid) for (result in results) {
                    val failure = result.shouldBeInstanceOf<CertificateValidationResult.Failure>()
                    // A rejection for an unrelated reason must remain a failure of this test.
                    failure.validatorFailures.any { it.validatorName in case.expectedValidators } shouldBe true
                }
            }
        }
    }
}

@Serializable
private data class PublicPathCorpus(val certificates: Map<String, String>, val cases: List<PublicPathCase>)

@Serializable
private data class PublicPathCase(
    val source: String,
    val id: String,
    val sourceUrl: String,
    val description: String,
    val expectedValid: Boolean,
    val anchors: List<String>,
    val paths: List<List<String>>,
    val validationTime: String,
    val expectedEku: List<String> = emptyList(),
    val initialPolicies: List<String> = emptyList(),
    val explicitPolicyRequired: Boolean = false,
    val anyPolicyInhibited: Boolean = false,
    val policyMappingInhibited: Boolean = false,
    val expectedValidators: List<String> = emptyList(),
    val allowDecodeRejection: Boolean = false,
    val allowUnsupportedCryptoAtDecode: Boolean = false,
)
