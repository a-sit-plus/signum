package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.TrustAnchor

import at.asitplus.signum.indispensable.pki.SignumPkix

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.supreme.shouldBeInvalid
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate

@OptIn(ExperimentalPkiApi::class)
/**
 * NIST - Public Key Interoperability Test Suite (PKITS)
 * Certification Path Validation
 */
val NistPkiTestSuite by matrixSuite {
    SignumPkix.install()

    val testSuite = json.decodeFromString<List<NistTestCase>>(resourceText("NIST-PKITS.json"))

    testSuite.asData(nameFn = { it.name }) test { testCase ->
        catchingUnwrapped {
            val trustAnchor = TrustAnchor.Certificate(
                X509Certificate.decodeFromPem(testCase.root)
            )

            val intermediates = testCase.intermediates.map {
                X509Certificate.decodeFromPem(it)
            }

            val leaf = X509Certificate.decodeFromPem(testCase.leaf)

            val chain = AnchoredCertificateChain((listOf(leaf) + intermediates.reversed()), trustAnchor)

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
                result.isValid shouldBe true
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
        }.onFailure {
            testCase.isSuccessful shouldBe false
            it.printStackTrace()
        }
    }
}
