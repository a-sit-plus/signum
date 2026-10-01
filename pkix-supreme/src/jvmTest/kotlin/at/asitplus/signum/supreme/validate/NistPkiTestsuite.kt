package at.asitplus.signum.supreme.validate
import at.asitplus.awesn1.serialization.DER

import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.signum.indispensable.pki.SignumPkix
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Instant
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate

/**
 * The 151 imported PKITS path cases, not the complete suite (in particular, no CRL tests).
 * Source: https://csrc.nist.gov/projects/pki-testing
 * Assertions: https://csrc.nist.gov/csrc/media/projects/pki-testing/documents/pkits.pdf
 * PKITS targets X.509/RFC 3280, the predecessor of RFC 5280, not CABF/WebPKI.
 *
 * The local JSON previously inverted the two valid notBefore cases (PKITS 4.2.3/4.2.4).
 * RFC 5280 6.1.3(a)(2) checks validity at the evaluation time, not interval containment in the issuer.
 * https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3
 */
@OptIn(ExperimentalPkiApi::class)
val NistPkitsPathTests by matrixSuite {
    SignumPkix.install()
    val cases = json.decodeFromString<List<NistTestCase>>(resourceText("NIST-PKITS.json"))

    cases.asData(nameFn = { it.name }) test { testCase ->
        val trustAnchor = TrustAnchor.Certificate(DER.decodeFromPem<X509Certificate>(testCase.root))
        val intermediates = testCase.intermediates.map { DER.decodeFromPem<X509Certificate>(it) }
        val leaf = DER.decodeFromPem<X509Certificate>(testCase.leaf)
        val chain = AnchoredCertificateChain(listOf(leaf) + intermediates.reversed(), trustAnchor)
        val context = CertificateValidationContext(
            // Reproducible time inside the ordinary fixture validity periods (2010-2030).
            date = Instant.parse("2025-01-01T00:00:00Z"),
            allowIncludedTrustAnchor = false,
            trustAnchors = setOf(trustAnchor),
            explicitPolicyRequired = testCase.explicitPolicyRequired,
            initialPolicies = testCase.initialPolicies.map { ObjectIdentifier(it) }.toSet(),
            anyPolicyInhibited = testCase.anyPolicyInhibited,
            policyMappingInhibited = testCase.policyMappingInhibited,
            // PKITS 4.7.4/4.7.5 require CRL-signing capability. The imported JSON has no CRLs:
            // these cases exercise ONLY that KU prerequisite, not actual revocation checking.
            // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.3.3 (f)
            supportRevocationChecking = testCase.name.startsWith("Key Usage:") &&
                    testCase.name.contains("cRLSign False"),
        )
        val result = chain.validate(ValidatorFactory.RFC5280, context)
        // Never catch assertions as an expected validation failure. A parser exception is also a
        // harness failure here; negative cases must return a failure from the expected validator.
        withClue("${testCase.name}: $result") {
            result.isValid shouldBe testCase.isSuccessful
            if (!testCase.isSuccessful) {
                val failure = result.shouldBeInstanceOf<CertificateValidationResult.Failure>()
                failure.validatorFailures.any { it.validatorName == testCase.failedValidator } shouldBe true
            }
        }
    }
}
