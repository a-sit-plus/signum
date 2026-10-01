package at.asitplus.signum.supreme.validate
import at.asitplus.awesn1.serialization.DER

import at.asitplus.awesn1.*
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.SignumPkix
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlin.time.Instant
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate

val json = Json { ignoreUnknownKeys = true }

/**
 * Imported vectors: https://github.com/C2SP/x509-limbo
 * RFC-labelled vectors include section 4 issuance linting, not just section 6.1 path checks.
 * Preserve upstream expected_result and document every different basic-path expectation below.
 * WebPKI/BetterTLS namespaces are not run: this adapter does not check TLS peer identity.
 */
@OptIn(ExperimentalPkiApi::class)
val LimboRfc5280PathTests by matrixSuite {
    SignumPkix.install()
    val suite = json.decodeFromString<LimboSuite>(resourceText("limbo.json"))
    val candidates = suite.testcases.filter {
        it.id.startsWith("rfc5280::") || it.id.startsWith("pathlen::") || it.id.startsWith("online::")
    }

    // RFC 5280 6.1 expressly separates section 4 issuance conformance from path validation:
    // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1
    val basicPathSuccess = buildMap {
        // Anchors supply trusted names/keys, not certificates to be revalidated (6.1.1(d)).
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.1
        listOf(
            "rfc5280::aki::critical-aki",
            "rfc5280::aki::cross-signed-root-missing-aki",
            "rfc5280::ski::critical-ski",
            "rfc5280::ski::root-missing-ski",
            "rfc5280::validity::expired-root",
            "rfc5280::unknown-critical-extension-root",
            "rfc5280::root-missing-basic-constraints",
            "rfc5280::root-non-critical-basic-constraints",
            "rfc5280::root-inconsistent-ca-extensions",
        ).forEach { put(it, "Trust-anchor issuance/profile requirements are not path checks; 6.1.1(d).") }
        listOf(
            "rfc5280::aki::leaf-missing-aki",
            "rfc5280::aki::intermediate-missing-aki",
            "rfc5280::ski::intermediate-missing-ski",
        ).forEach { put(it, "Identifier presence is issuance conformance (4.2.1.1-2), not a 6.1 check.") }
        listOf("too-long", "zero").forEach {
            put("rfc5280::serial::$it", "Serial limits are issuance rules (4.1.2.2); see 6.1's profile distinction.")
        }
        put("rfc5280::san::noncritical-with-empty-subject", "SAN criticality is an issuance rule (4.2.1.6).")
        put("rfc5280::ca-empty-subject", "Nonempty CA subject is an issuance rule (4.1.2.6).")
        put("rfc5280::leaf-ku-keycertsign", "KU/cA consistency is issuance conformance (4.2.1.3); no signing is requested of the target.")
        // 6.1.4(g)/(i) process recognized NC/PC regardless of their criticality.
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4
        put("rfc5280::nc::permitted-dns-match-noncritical", "Process recognized constraints; criticality is an issuance rule (4.2.1.10).")
        put("rfc5280::pc::ica-noncritical-pc", "Process recognized policy constraints; criticality is an issuance rule (4.2.1.11).")
        listOf("noncritical", "critical").forEach {
            put("rfc5280::nc::not-allowed-in-ee-$it", "Section 6.1.4 prepares subsequent certificates; target NC has no descendants here.")
        }
        // TLS peer identity is separate from certification-path validity.
        // https://www.rfc-editor.org/rfc/rfc9525.html#section-6
        put("rfc5280::ca-as-leaf-wrong-san", "Expected peer-name matching is outside this basic-path adapter (RFC 9525 section 6).")
    }
    val exclusions = mapOf(
        // The current constructor attaches anchors to a fixed path; it does not search issuer graphs.
        // Path discovery is outside RFC 5280 6.1, but these remain untested Limbo capabilities.
        "rfc5280::nc::nc-forbids-alternate-chain-ica" to "Requires alternate-path discovery.",
        "rfc5280::nc::nc-forbids-same-chain-ica" to "Requires alternate-path discovery across two anchors.",
        "rfc5280::root-and-intermediate-swapped" to "Requires reordering an issuer pool into a path.",
        // These imported vectors omit the intermediate described in their own text. The leaf's
        // issuer does not match the supplied root. Reporting their generic rejection as a BC/KU
        // conformance pass would test the wrong property.
        "rfc5280::intermediate-ca-missing-basic-constraints" to "Fixture omits the intermediate whose BC should be tested.",
        "rfc5280::ica-ku-keycertsign" to "Fixture omits the intermediate whose KU should be tested.",
        // The same non-self-issued certificate is both peer and sole trust anchor: this is direct
        // trust, not a nonempty certification path. Its serial is still exercised by issuance linting.
        "rfc5280::serial::negative" to "Directly trusted peer; no issuer/path supplied for a basic-path test.",
    ) + candidates.filter { it.max_chain_depth != null }.associate {
        it.id to "Limbo max_chain_depth is caller policy, distinct from certificate pathLenConstraint; not implemented."
    }
    val decodeFailures = setOf("rfc5280::duplicate-extensions", "rfc5280::mismatching-signature-algorithm")
    require((basicPathSuccess.keys + exclusions.keys + decodeFailures).all { id -> candidates.any { it.id == id } })

    candidates.filter { it.id !in exclusions && it.id !in decodeFailures }
        .asData(nameFn = { "Basic path: ${it.id}" }) test { testcase ->
            val rationale = basicPathSuccess[testcase.id]
            val expected = rationale != null || testcase.expected_result == "SUCCESS"
            // ee-empty-issuer also mismatches its anchor's subject. Its rejection exercises
            // 6.1.3(a)(4) name chaining, not a standalone section 4 empty-issuer check.
            // Limbo's fractional notAfter vector explicitly calls its result ambiguous. Keep the
            // existing seconds-flooring convention; it is an interoperability choice, not an RFC MUST.
            // https://x509-limbo.com/testcases/rfc5280/#rfc5280validitynotafter-fractional
            val result = validate(testcase)
            withClue("${testcase.id}; upstream=${testcase.expected_result}; basicPath=$expected; ${rationale ?: testcase.description}; $result") {
                result.isValid shouldBe expected
                if (!expected) {
                    val expectedValidator = when {
                        testcase.id.startsWith("rfc5280::nc::") || testcase.id.startsWith("rfc5280::san::") -> "NameConstraintsValidator"
                        testcase.id.startsWith("rfc5280::validity::") -> "TimeValidityValidator"
                        testcase.id.startsWith("rfc5280::eku::") -> "KeyUsageValidator"
                        testcase.id.startsWith("pathlen::") || testcase.id == "rfc5280::intermediate-ca-without-ca-bit" -> "BasicConstraintsValidator"
                        testcase.id.contains("unknown-critical-extension") || testcase.id == "rfc5280::ee-critical-aia-invalid" -> "CriticalCertificateExtensions"
                        else -> "ChainValidator"
                    }
                    result.shouldBeInstanceOf<CertificateValidationResult.Failure>().validatorFailures.any {
                        it.validatorName == expectedValidator
                    } shouldBe true
                }
            }
        }

    // A parse-time rejection is distinct from a returned path-validation failure.
    "RFC 5280 4.1.1.2: inner and outer signature algorithms must agree (decoder)" {
        val testcase = candidates.single { it.id == "rfc5280::mismatching-signature-algorithm" }
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2
        shouldThrow<IllegalArgumentException> { validate(testcase) }
            .message shouldStartWith "Inner TBS certificate signature algorithm"
    }
    "RFC 5280 4.2: duplicate extensions are rejected by the decoder" {
        val testcase = candidates.single { it.id == "rfc5280::duplicate-extensions" }
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2
        shouldThrow<IllegalArgumentException> { validate(testcase) }
            .message shouldBe "Multiple extensions with the same OID found"
    }

    context("Optional issuance linting; additional to basic path validation") {
        // These are partial section 4 checkers, not a full RFC profile or a WebPKI preset.
        val profileFactory = ValidatorFactory { context ->
            with(ValidatorFactory.RFC5280) { generate(context) } +
                    listOf(CertValidityValidator(), KeyIdentifierValidator())
        }
        candidates.filter {
            it.id.startsWith("rfc5280::aki::") || it.id.startsWith("rfc5280::ski::") ||
                    it.id.startsWith("rfc5280::serial::") || it.id == "rfc5280::san::noncritical-with-empty-subject"
        }.asData(nameFn = { "Issuance checks: ${it.id}" }) test { testcase ->
            withClue("${testcase.id}: ${testcase.description}") {
                val result = validate(testcase, profileFactory)
                result.isValid shouldBe (testcase.expected_result == "SUCCESS")
                if (testcase.expected_result == "FAILURE") {
                    result.shouldBeInstanceOf<CertificateValidationResult.Failure>().validatorFailures.any {
                        it.validator is CertValidityValidator || it.validator is KeyIdentifierValidator
                    } shouldBe true
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
@Throws(Asn1Exception::class)
suspend fun validate(
    testcase: LimboTestcase,
    validatorFactory: ValidatorFactory = ValidatorFactory.RFC5280,
): CertificateValidationResult {
    val trustAnchors = testcase.trusted_certs.map { pem ->
        TrustAnchor.Certificate(DER.decodeFromPem<X509Certificate>(pem))
    }

    val intermediates = testcase.untrusted_intermediates.map { pem ->
        DER.decodeFromPem<X509Certificate>(pem)
    }

    val leaf = DER.decodeFromPem<X509Certificate>(testcase.peer_certificate)

    val chain = AnchoredCertificateChain((listOf(leaf) + intermediates.reversed()), trustAnchors.first())
    val validationTime = testcase.validation_time?.let(Instant::parse) ?: Instant.parse("2025-01-01T00:00:00Z")

    val context = CertificateValidationContext(
        allowIncludedTrustAnchor = false,
        trustAnchors = trustAnchors.toSet(),
        expectedEku = testcase.extended_key_usage.map { requireNotNull(extendedKeyUsages[it]) { "Unsupported EKU: $it" } }.toSet(),
        date = validationTime
    )

    // This adapter validates a supplied path, not an unordered issuer pool. It intentionally does
    // not implement SERVER/CLIENT identity matching, signature algorithm policy, key_usage,
    // max_chain_depth or CRL processing. See the named exclusions above and the Limbo schema:
    // https://github.com/C2SP/x509-limbo/blob/main/limbo-schema.json
    return chain.validate(validatorFactory, context)
}

val extendedKeyUsages: Map<String, ObjectIdentifier> = mapOf(
    // RFC 5280 EKUs
    "serverAuth" to KnownOIDs.serverAuth,
    "clientAuth" to KnownOIDs.clientAuth
)
