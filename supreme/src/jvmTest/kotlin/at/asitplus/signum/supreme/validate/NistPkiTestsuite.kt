package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.shouldBeInvalid
import at.asitplus.signum.supreme.shouldBeValid
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.coroutines.runBlocking

@OptIn(ExperimentalPkiApi::class)
/**
 * NIST - Public Key Interoperability Test Suite (PKITS)
 * Certification Path Validation
 */
val NistPkiTestSuite by testSuite{
    
    val testSuite = json.decodeFromString<List<NistTestCase>>(resourceText("NIST-PKITS.json"))

    runBlocking {
        SystemCrlCache.initialize("./src/jvmTest/resources/crls/PKITS_crl")
    }
    testSuite.forEach { testCase ->
        test(testCase.name) {

            val trustAnchor = TrustAnchor.Certificate(
                X509Certificate.decodeFromPem(testCase.root).getOrThrow()
            )

            val intermediates = testCase.intermediates.map {
                X509Certificate.decodeFromPem(it).getOrThrow()
            }

            val leaf = X509Certificate.decodeFromPem(testCase.leaf).getOrThrow()

            val chain =
                AnchoredCertificateChain((listOf(leaf) + intermediates.reversed()), trustAnchor)

            val context = CertificateValidationContext(
                allowIncludedTrustAnchor = false,
                explicitPolicyRequired = testCase.explicitPolicyRequired,
                initialPolicies = testCase.initialPolicies.map { ObjectIdentifier(it) }.toSet(),
                anyPolicyInhibited = testCase.anyPolicyInhibited,
                policyMappingInhibited = testCase.policyMappingInhibited,
                supportRevocationChecking = true
            )

            val result = chain.validate(context)
            if (testCase.isSuccessful) {
                if (testCase.name.contains("4.")) {
                    if (!result.isValid) {
                        result.shouldBeInvalid()
                        result.validatorFailures
                            .firstOrNull { it.validatorName == "CrlRevocationValidator" }  shouldBe null
                    } else result.shouldBeValid()
                } else {
                    result.shouldBeValid()
                }
            } else {
                result.shouldBeInvalid()
                val validatorFailure =
                    result.validatorFailures.firstOrNull {
                        it.validator!!::class.simpleName == testCase.failedValidator
                    }

                validatorFailure shouldNotBe null
                if (testCase.failedValidator == "TimeValidityValidator") {
                    validatorFailure!!.errorMessage shouldContain testCase.errorMessage!!
                } else {
                    validatorFailure!!.errorMessage shouldBe testCase.errorMessage
                }
            }
        }
    }
}
