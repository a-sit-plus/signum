package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.validate.BasicConstraintsValidator
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.Json

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
                    result.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator} shouldNotBe null
                } else {
                    result.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator} shouldBe null
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
    val context = CertificateValidationContext(trustAnchors = trustAnchors.toSet())

    return chain.validate(context)
}