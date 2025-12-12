package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Clock
import kotlin.time.Instant


@OptIn(ExperimentalPkiApi::class)
val ValidateChainWithSystemTrustStoreTest by testSuite{

    val testSuiteLimbo = json.decodeFromString<LimboSuite>(resourceText("limbo.json"))

    // we are sending trust anchors as part of the chain, but expecting that they are included in system trust store, so they will be omitted from the chain during validation
    context("online testcases") {
        val onlineTests = testSuiteLimbo.testcases.filter {
            it.id.contains("online", ignoreCase = true)
                    && !it.id.contains("online::stackoverflow.com", ignoreCase = true)

        }
        onlineTests.forEach {
            test("Online testcase validated using system trust store: ${it.id}") {
                val trustAnchors = it.trusted_certs.map { pem ->
                    X509Certificate.decodeFromPem(pem).getOrThrow()
                }

                val intermediates = it.untrusted_intermediates.map { pem ->
                    X509Certificate.decodeFromPem(pem).getOrThrow()
                }

                val leaf = X509Certificate.decodeFromPem(it.peer_certificate).getOrThrow()

                val chain: CertificateChain = listOf(leaf) + intermediates.reversed() + trustAnchors.reversed()
                val validationTime = it.validation_time?.let(Instant::parse) ?: Clock.System.now()

                val context = CertificateValidationContext(
                    allowIncludedTrustAnchor = true, // default is true, but for the clarity
                    expectedEku = it.extended_key_usage.mapNotNull { extendedKeyUsages[it] }.toSet(),
                    date = validationTime
                )

                val result = chain.validate(context)

                if (it.expected_result == "FAILURE") {
                    result.isValid shouldBe false
                } else {
                    result.isValid shouldBe true
                }

            }
        }
    }
}

