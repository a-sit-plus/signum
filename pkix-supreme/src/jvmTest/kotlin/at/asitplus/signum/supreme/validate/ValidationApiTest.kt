package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.installPkix
import at.asitplus.signum.Signum
import kotlinx.serialization.decodeFromByteArray

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.supreme.shouldBeInvalid
import at.asitplus.signum.supreme.shouldBeValid
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import java.util.*
import kotlin.time.Instant
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate

@OptIn(ExperimentalPkiApi::class)
val ValidationApiTest by matrixSuite {
    Signum.installPkix()

    val testSuiteLimbo = json.decodeFromString<LimboSuite>(resourceText("limbo.json"))

    // Saved Limbo snapshots; no network/system trust-store lookup or TLS identity matching.
    // Included anchors are removed because they are explicitly trusted in the context (6.1.1(d)).
    // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.1
    context("saved online snapshots with explicitly supplied roots") {
        val onlineTests = testSuiteLimbo.testcases.filter {
            it.id.startsWith("online::")

        }
        onlineTests.asData(nameFn = { "Saved path: ${it.id} (${it.expected_result})" }) test {
            val trustAnchors = it.trusted_certs.map { pem ->
                Signum.Der.decodeFromPem<X509Certificate>(pem)
            }

            val intermediates = it.untrusted_intermediates.map { pem ->
                Signum.Der.decodeFromPem<X509Certificate>(pem)
            }

            val leaf = Signum.Der.decodeFromPem<X509Certificate>(it.peer_certificate)

            val chain: CertificateChain = listOf(leaf) + intermediates.reversed() + trustAnchors.reversed()
            val validationTime = Instant.parse(requireNotNull(it.validation_time) { "Snapshot needs a recorded validation time: ${it.id}" })

            val context = CertificateValidationContext(
                trustAnchors = setOf(TrustAnchor.Certificate(chain.root)),
                allowIncludedTrustAnchor = true, // default is true, but for the clarity
                expectedEku = it.extended_key_usage.map { requireNotNull(extendedKeyUsages[it]) { "Unsupported EKU: $it" } }.toSet(),
                date = validationTime
            )

            val result = chain.buildPathAndValidate(context)

            withClue("leaf: " + it.peer_certificate) {
                withClue("intermeds: " + it.untrusted_intermediates.joinToString(separator = ", ")) {
                    withClue("anchors: " + it.trusted_certs.joinToString(separator = ", ")) {
                        withClue("result: $result") {
                            if (it.expected_result == "FAILURE") result.shouldBeInvalid()
                            else result.shouldBeValid()
                        }
                    }
                }
            }
        }
    }

    "Custom attestation policy: validate intermediates at a historical time" {
        val attestationProofB64 = listOf(
            """MIIC+jCCAqCgAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCVVMxEzARBgNVB
                    AgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZ
                    DE7MDkGA1UEAwwyQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlc
                    m1lZGlhdGUwHhcNNzAwMTAxMDAwMDAwWhcNNjkxMjMxMjM1OTU5WjAfMR0wGwYDVQQDDBRBb
                    mRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIEAthaOZ2+nZ
                    ZyYdoeLYNL5yZozzfMdrfrZcG2RI1juriVparubkzxZGCs4KcReh1aDhWFsDxQWYAeJLcFN8
                    rOjggFhMIIBXTALBgNVHQ8EBAMCB4AwggErBgorBgEEAdZ5AgERBIIBGzCCARcCAQQKAQACA
                    SkKAQAEEETfQo1OyOc6bwoew974v2gEADCB8qEIMQYCAQICAQOiAwIBA6MEAgIBAKUIMQYCA
                    QICAQSqAwIBAb+DdwIFAL+FPQgCBgGHj7zJmL+FPgMCAQC/hUBMMEoEIAAAAAAAAAAAAAAAA
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                    AAAAAAAAL+FQQUCAwGtsL+FQgUCAwMVG7+FRU8ETTBLMSUwIwQeYXQuYXNpdHBsdXMuYXR0Z
                    XN0YXRpb25fY2xpZW50AgEBMSIEIDS5dixNbJDUhDGUDFe95zFCWLJkIO/hasf3J08NMwrVM
                    AAwHwYDVR0jBBgwFoAUP/ys1hqxOp6BILjVJRzFZbsekakwCgYIKoZIzj0EAwIDSAAwRQIgW
                    CsSigJsOLe9hli462AL/TuPqLuuIKelSVEe/PsnrWUCIQC+JExSC5l3slEBhDKxMD3otjwr0
                    DK0Jav50CzyK80ILg==
                    """,
            """MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDV
                    QQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nb
                    GUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU
                    29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2M
                    DlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ
                    2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlI
                    FNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49A
                    wEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZ
                    jW8U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfB
                    gNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA
                    1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqR
                    Z9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7
                    """,
            """MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVU
                    zETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UEC
                    gwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtle
                    XN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwM
                    TA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVB
                    AcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kc
                    m9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb
                    290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/S
                    Q59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEF
                    Mit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPM
                    A8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho
                    ++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytT
                    ySn502vQX3xvw==
                    """
        )

        val chain: CertificateChain = attestationProofB64.map {
            Signum.Der.decodeFromByteArray<X509Certificate>(
                Base64.getMimeDecoder()
                    .decode(it)
            )!!
        }

        chain.buildPathAndValidate(
            CertificateValidationContext(
                date = Instant.parse("2026-11-02T00:00:00Z"),
                trustAnchors = setOf(TrustAnchor.Certificate(chain.root)),
            )
        ).isValid shouldBe false

        val customValidatorFactory = ValidatorFactory { context ->
            val validators = ValidatorFactory.RFC5280.run {
                chain.generate(
                    context = context
                )
            }.toMutableList()
            // Explicit application override, not basic validation at context.date (6.1.3(a)(2)).
            // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3
            validators.removeAll { it is TimeValidityValidator }
            validators.add(AttestationTimeValidator(Instant.parse("2020-01-01T00:00:00Z")))
            validators
        }

        chain.buildPathAndValidate(
            customValidatorFactory,
            CertificateValidationContext(
                trustAnchors = setOf(TrustAnchor.Certificate(chain.root))
            )
        ).isValid shouldBe true
    }
}

// Illustrative application policy; the caller supplies the historical time. This example does not
// establish that the time is authentic and deliberately does not check leaf validity or revocation.
class AttestationTimeValidator(private val attestationTime: Instant) : CertificateValidator {

    @ExperimentalPkiApi
    override suspend fun check(
        currCert: X509Certificate,
    ): Set<ObjectIdentifier> {
        currCert.checkValidityAt(attestationTime)
        return emptySet()
    }

    @ExperimentalPkiApi
    override suspend fun validate(
        anchoredChain: AnchoredCertificateChain,
        context: CertificateValidationContext
    ): Map<X509Certificate, Set<ObjectIdentifier>> {
        anchoredChain.chain.forEach { if (it != anchoredChain.chain.leaf) check(it) }
        return emptyMap()
    }
}
