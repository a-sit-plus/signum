package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.TrustAnchor

import at.asitplus.signum.indispensable.pki.SignumPkix

import at.asitplus.awesn1.*
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.KeyIdentifierException
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.supreme.shouldBeInvalid
import at.asitplus.signum.supreme.shouldBeValid
import at.asitplus.testballoon.matrix.Indexes
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Instant
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate

val json = Json { ignoreUnknownKeys = true }

@OptIn(ExperimentalPkiApi::class)
val LimboTests by matrixSuite {
    SignumPkix.install()

    val testSuiteLimbo = json.decodeFromString<LimboSuite>(resourceText("limbo.json"))

    context("basicConstraints test") {
        val basicConstraintTests = testSuiteLimbo.testcases.filter {
            it.id.contains("basic-constraints", ignoreCase = true)
        }
        basicConstraintTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
//                    result.validatorFailures.firstOrNull { it.validator is TrustAnchorValidator } shouldNotBe null
            } else {
                result.shouldBeValid()
            }
        }
    }

    context("pathLen test") {
        val pathLenTests = testSuiteLimbo.testcases.filter {
            it.id.contains("pathlen", ignoreCase = true) && !it.id.contains("exhausted", ignoreCase = true)
        }
        pathLenTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
                result.validatorFailures.firstOrNull { it.validator is BasicConstraintsValidator } shouldNotBe null
            } else {
                result.shouldBeValid()
            }
        }
    }

    //Aki tests from webpki-test-suite excluded, since AKI and SKI match is not required by RFC5280
    context("Authority key identifier tests") {
        val akiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::aki", ignoreCase = true)
        }
        akiTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
                result.validatorFailures[0].cause.shouldBeInstanceOf<KeyIdentifierException>()
            } else {
                result.shouldBeValid()
            }
        }
    }

    context("EKU tests") {
        val akiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::eku", ignoreCase = true)
        }
        akiTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.id.contains("empty", ignoreCase = true)) {
                result.shouldBeInvalid()
                val failure = result.validatorFailures.firstOrNull { it.validator is KeyUsageValidator }
                failure?.cause?.message shouldBe "Empty EKU extension in leaf certificate."
            } else if (it.id.contains("wrong", ignoreCase = true)) {
                result.shouldBeInvalid()
                val failure = result.validatorFailures.firstOrNull { it.validator is KeyUsageValidator }
                failure?.cause?.message shouldBe "Missing EKU 1.3.6.1.5.5.7.3.1 in leaf certificate."
            } else {
                result.shouldBeValid()
            }
        }
    }

    context("Name constraints tests") {
        val ncTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::nc", ignoreCase = true)
                    && !it.id.contains("rfc5280::nc::nc-forbids-same-chain-ica", ignoreCase = true)
                    && !it.id.contains("rfc5280::nc::nc-forbids-alternate-chain-ica", ignoreCase = true)
        }
        ncTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
                result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldNotBe null
            } else {
                result.shouldBeValid()
            }

        }
    }

    context("san tests") {
        val sanTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::san", ignoreCase = true)
                    && !it.id.contains("malformed", ignoreCase = true)
        }
        sanTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
                result.validatorFailures.size shouldNotBe 0
            } else {
                result.shouldBeValid()
            }

        }
    }

    "rfc5280::san::malformed" {
        val test = testSuiteLimbo.testcases.first { it.id.contains("rfc5280::san::malformed", ignoreCase = true) }
        validate(test).shouldBeInstanceOf<CertificateValidationResult.Failure>()
    }

    "rfc5280::mismatching-signature-algorithm" {
        val test = testSuiteLimbo.testcases.first {
            it.id.contains(
                "rfc5280::mismatching-signature-algorithm",
                ignoreCase = true
            )
        }
        shouldThrow<IllegalArgumentException> {
            validate(test)
        }.message shouldStartWith "Inner TBS certificate signature algorithm"
    }

    context("online testcases") {
        val onlineTests = testSuiteLimbo.testcases.filter {
            it.id.contains("online", ignoreCase = true)
                    && !it.id.contains("online::stackoverflow.com", ignoreCase = true)

        }
        onlineTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
                result.validatorFailures.size shouldNotBe 0
            } else {
                result.shouldBeValid()
            }

        }
    }

    context("Subject Key Identifier testcases") {
        val skiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::ski", ignoreCase = true)
        }
        skiTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
                result.validatorFailures.size shouldNotBe 0
            } else {
                result.shouldBeValid()
            }

        }
    }

    context("Certificate serial number tests") {
        val skiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::serial", ignoreCase = true)
        }
        skiTests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)
            result.shouldBeInvalid()
            val failure = result.validatorFailures.firstOrNull { it.validator is CertValidityValidator }

            if (it.id.contains("too-long", ignoreCase = true)) {
                failure?.cause?.message shouldContain "Serial number too long"
            } else if (it.id.contains("negative", ignoreCase = true)) {
                failure?.cause?.message shouldContain "Serial number must be positive"
            } else {
                failure?.cause?.message shouldContain "Serial number must not be zero"
            }

        }
    }

    context("time validity tests") {
        val skiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::validity", ignoreCase = true)
        }
        skiTests.asData(nameFn = { "Limbo testcase: ${it.id}" }, replay = Indexes(6L)) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
                result.validatorFailures.firstOrNull { it.validator is TimeValidityValidator } shouldNotBe null
            } else {
                result.shouldBeValid()
            }

        }
    }

    context("rfc5280 tests") {
        val excluded = listOf(
            "basic-constraints",
            "pathlen",
            "rfc5280::aki",
            "rfc5280::eku",
            "rfc5280::nc",
            "rfc5280::validity",
            "rfc5280::serial",
            "rfc5280::ski",
            "rfc5280::san",
            "online",
            "betterTls",
            "rfc5280::ca-as-leaf-wrong-san",
            "rfc5280::root-and-intermediate-swapped",
            "rfc5280::unknown-critical-extension-root",
            "rfc5280::root-inconsistent-ca-extensions",
            "rfc5280::mismatching-signature-algorithm",
            "rfc5280::duplicate-extensions",
            "rfc5280::pc::ica-noncritical-pc"
        )

        val tests = testSuiteLimbo.testcases.filter { tc ->
            tc.id.contains("rfc5280", ignoreCase = true) &&
                    excluded.none { tc.id.contains(it, ignoreCase = true) }
        }
        tests.asData(nameFn = { "Limbo testcase: ${it.id}" }) test {
            val result = validate(it)

            if (it.expected_result == "FAILURE") {
                result.shouldBeInvalid()
                result.validatorFailures.size shouldNotBe 0
            } else {
                result.shouldBeValid()
            }

        }
    }

    "rfc5280::duplicate-extensions" {
        val test = testSuiteLimbo.testcases.first { it.id.contains("rfc5280::duplicate-extensions", ignoreCase = true) }

        shouldThrow<IllegalArgumentException> {
            validate(test)
        }.also { it.message shouldBe "Multiple extensions with the same OID found" }
    }
}

fun resourceText(path: String): String {
    val stream = Thread.currentThread().contextClassLoader.getResourceAsStream(path)
        ?: error("Resource not found: $path")
    return stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
}

@OptIn(ExperimentalPkiApi::class)
@Throws(Asn1Exception::class)
suspend fun validate(testcase: LimboTestcase): CertificateValidationResult {
    val trustAnchors = testcase.trusted_certs.map { pem ->
        TrustAnchor.Certificate(X509Certificate.decodeFromPem(pem))
    }

    val intermediates = testcase.untrusted_intermediates.map { pem ->
        X509Certificate.decodeFromPem(pem)
    }

    val leaf = X509Certificate.decodeFromPem(testcase.peer_certificate)

    val chain = AnchoredCertificateChain((listOf(leaf) + intermediates.reversed()), trustAnchors.first())
    val validationTime = testcase.validation_time?.let(Instant::parse) ?: Clock.System.now()

    val context = CertificateValidationContext(
        allowIncludedTrustAnchor = false,
        trustAnchors = trustAnchors.toSet(),
        expectedEku = testcase.extended_key_usage.mapNotNull { extendedKeyUsages[it] }.toSet(),
        date = validationTime
    )

    return chain.validate(context)
}

val extendedKeyUsages: Map<String, ObjectIdentifier> = mapOf(
    // RFC 5280 EKUs
    "serverAuth" to KnownOIDs.serverAuth,
    "clientAuth" to KnownOIDs.clientAuth
)