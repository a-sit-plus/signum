package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.clientAuth
import at.asitplus.signum.indispensable.asn1.serverAuth
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.validate.BasicConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.CertValidityValidator
import at.asitplus.signum.indispensable.pki.validate.KeyIdentifierValidator
import at.asitplus.signum.indispensable.pki.validate.KeyUsageValidator
import at.asitplus.signum.indispensable.pki.validate.NameConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.TimeValidityValidator
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Instant

private val json = Json { ignoreUnknownKeys = true }

@OptIn(ExperimentalPkiApi::class)
val LimboTests by testSuite{

    val testSuiteLimbo = json.decodeFromString<LimboSuite>(resourceText("limbo.json"))

    context("basicConstraints test") {
        val basicConstraintTests = testSuiteLimbo.testcases.filter {
            it.id.contains("basic-constraints", ignoreCase = true)
        }
        basicConstraintTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)

                if (it.expected_result == "FAILURE") {
                    result.validatorFailures.firstOrNull {it.validator is TrustAnchorValidator} shouldNotBe null
                } else {
                    result.validatorFailures.firstOrNull {it.validator is TrustAnchorValidator} shouldBe null
                }
            }
        }
    }

    context("pathLen test") {
        val pathLenTests = testSuiteLimbo.testcases.filter {
            it.id.contains("pathlen", ignoreCase = true) && !it.id.contains("exhausted", ignoreCase = true)
        }
        pathLenTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)

                if (it.expected_result == "FAILURE") {
                    result.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator } shouldNotBe null
                } else {
                    result.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator} shouldBe null
                }
            }
        }
    }

    //Aki tests from webpki-test-suite excluded, since AKI and SKI match is not required by RFC5280
    context("Authority key identifier tests") {
        val akiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::aki", ignoreCase = true)
        }
        akiTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)

                if (it.expected_result == "FAILURE") {
                    result.validatorFailures.firstOrNull { it.validator is KeyIdentifierValidator } shouldNotBe null
                } else {
                    result.validatorFailures.firstOrNull { it.validator is KeyIdentifierValidator } shouldBe null
                    result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
                }
            }
        }
    }

    context("EKU tests") {
        val akiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::eku", ignoreCase = true)
        }
        akiTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)
                val failure = result.validatorFailures.firstOrNull { it.validator is KeyUsageValidator }

                if (it.id.contains("empty", ignoreCase = true)) {
                    failure?.cause?.message shouldBe "Empty EKU extension in leaf certificate."
                } else if (it.id.contains("wrong", ignoreCase = true)) {
                    failure?.cause?.message shouldBe "Missing EKU 1.3.6.1.5.5.7.3.1 in leaf certificate."
                } else {
                    failure shouldBe null
                }
            }
        }
    }

    context("Name constraints tests") {
        val ncTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::nc", ignoreCase = true)
                    && !it.id.contains("rfc5280::nc::nc-forbids-same-chain-ica", ignoreCase = true)
                    && !it.id.contains("rfc5280::nc::nc-forbids-alternate-chain-ica", ignoreCase = true)
        }
        ncTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)

                if (it.expected_result == "FAILURE") {
                    result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldNotBe null
                } else {
                    result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
                }

            }
        }
    }

    context("san tests") {
        val sanTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::san", ignoreCase = true)
                    && !it.id.contains("malformed", ignoreCase = true)
        }
        sanTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)

                if (it.expected_result == "FAILURE") {
                    result.validatorFailures.size shouldNotBe 0
                } else {
                    result.validatorFailures.size shouldBe 0
                }

            }
        }
    }

    "rfc5280::san::malformed" {
        val test = testSuiteLimbo.testcases.first {it.id.contains("rfc5280::san::malformed", ignoreCase = true)}

        shouldThrow<Asn1Exception> {
            validate(test)
        }
    }

    context("online testcases") {
        val onlineTests = testSuiteLimbo.testcases.filter {
            it.id.contains("online", ignoreCase = true)
                    && !it.id.contains("online::stackoverflow.com", ignoreCase = true)

        }
        onlineTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)

                if (it.expected_result == "FAILURE") {
                    result.validatorFailures.size shouldNotBe 0
                } else {
                    result.validatorFailures.size shouldBe 0
                }

            }
        }
    }

    context("Subject Key Identifier testcases") {
        val skiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::ski", ignoreCase = true)
        }
        skiTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)

                if (it.expected_result == "FAILURE") {
                    result.validatorFailures.size shouldNotBe 0
                } else {
                    result.validatorFailures.size shouldBe 0
                }

            }
        }
    }

    context("Certificate serial number tests") {
        val skiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::serial", ignoreCase = true)
        }
        skiTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)
                val failure = result.validatorFailures.firstOrNull { it.validator is CertValidityValidator }

                if (it.id.contains("too-long", ignoreCase = true)) {
                    failure?.cause?.message shouldBe "Serial number too long"
                } else if (it.id.contains("negative", ignoreCase = true)) {
                    failure?.cause?.message shouldBe "Serial number must be positive"
                } else {
                    failure?.cause?.message shouldBe "Serial number must not be zero"
                }

            }
        }
    }

    context("time validity tests") {
        val skiTests = testSuiteLimbo.testcases.filter {
            it.id.contains("rfc5280::validity", ignoreCase = true)
        }
        skiTests.forEach {
            test("Limbo testcase: ${it.id}") {
                val result = validate(it)

                if (it.expected_result == "FAILURE") {
                    if (it.id.contains("expired-root", ignoreCase = true))
                        result.validatorFailures.firstOrNull { it.validator is TrustAnchorValidator } shouldNotBe null
                    else
                        result.validatorFailures.firstOrNull { it.validator is TimeValidityValidator } shouldNotBe null
                } else {
                    result.validatorFailures.firstOrNull { it.validator is TimeValidityValidator } shouldBe null
                }

            }
        }
    }

}

fun resourceText(path: String): String {
    val stream = Thread.currentThread().contextClassLoader.getResourceAsStream(path)
        ?: error("Resource not found: $path")
    return stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
}

@OptIn(ExperimentalPkiApi::class)
suspend fun validate(testcase: LimboTestcase) : CertificateValidationResult {
    val trustAnchors = testcase.trusted_certs.map { pem ->
        TrustAnchor(X509Certificate.decodeFromPem(pem).getOrThrow())
    }

    val intermediates = testcase.untrusted_intermediates.map { pem ->
        X509Certificate.decodeFromPem(pem).getOrThrow()
    }

    val leaf = X509Certificate.decodeFromPem(testcase.peer_certificate).getOrThrow()

    val chain: CertificateChain = listOf(leaf) + intermediates.reversed()
    val validationTime = testcase.validation_time?.let(Instant::parse) ?: Clock.System.now()

    val context = CertificateValidationContext(
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