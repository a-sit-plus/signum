package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.shouldBeInvalid
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

@OptIn(ExperimentalPkiApi::class)
/**
 * NIST - Public Key Interoperability Test Suite (PKITS)
 * Certification Path Validation
 */
val NistPkiTestSuite by testSuite{

    val testSuite = json.decodeFromString<List<NistTestCase>>(resourceText("NIST-PKITS.json")).filter { tc ->
        !tc.name.contains("cRLSign", ignoreCase = true)
    }

    testSuite.forEach { testCase ->
        test(testCase.name) {

            val trustAnchors = TrustAnchor.Certificate(
                X509Certificate.decodeFromPem(testCase.root).getOrThrow()
            )

            val intermediates = testCase.intermediates.map {
                X509Certificate.decodeFromPem(it).getOrThrow()
            }

            val leaf = X509Certificate.decodeFromPem(testCase.leaf).getOrThrow()

            val chain: CertificateChain = listOf(leaf) + intermediates.reversed()

            val context = CertificateValidationContext(
                allowIncludedTrustAnchor = false,
                trustAnchors = setOf(trustAnchors),
                explicitPolicyRequired = testCase.explicitPolicyRequired,
                initialPolicies = testCase.initialPolicies.map { ObjectIdentifier(it) }.toSet(),
                anyPolicyInhibited = testCase.anyPolicyInhibited,
                policyMappingInhibited = testCase.policyMappingInhibited
            )

            val result = chain.validate(context)

            if (testCase.isSuccessful) {
                result.isValid shouldBe true
            } else {
                result.shouldBeInvalid()
                val validatorFailure =
                    result.validatorFailures.firstOrNull {
                        it.validator!!::class.simpleName == testCase.failedValidator
                    }

                validatorFailure shouldNotBe null
                validatorFailure!!.errorMessage shouldBe testCase.errorMessage
            }
        }
    }
}
