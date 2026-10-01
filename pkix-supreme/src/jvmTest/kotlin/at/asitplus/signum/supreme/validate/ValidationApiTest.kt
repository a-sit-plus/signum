package at.asitplus.signum.supreme.validate

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.supreme.shouldBeInvalid
import at.asitplus.signum.supreme.shouldBeValid
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import java.util.*
import kotlin.time.Clock
import kotlin.time.Instant
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate


@OptIn(ExperimentalPkiApi::class)
val ValidationApiTest by matrixSuite {
    SignumPkix.install()

    val testSuiteLimbo = json.decodeFromString<LimboSuite>(resourceText("limbo.json"))

    // we are sending trust anchors as part of the chain, but expecting that they are included in system trust store, so they will be omitted from the chain during validation
    context("online testcases") {
        val onlineTests = testSuiteLimbo.testcases.filter {
            it.id.contains("online", ignoreCase = true)
                    && !it.id.contains("online::stackoverflow.com", ignoreCase = true)

        }
        onlineTests.asData(nameFn = { "Online testcase validated using provided trusted roots: ${it.id} (${it.expected_result}" }) test {
            val trustAnchors = it.trusted_certs.map { pem ->
                X509Certificate.decodeFromPem(pem)
            }

            val intermediates = it.untrusted_intermediates.map { pem ->
                X509Certificate.decodeFromPem(pem)
            }

            val leaf = X509Certificate.decodeFromPem(it.peer_certificate)

            val chain: CertificateChain = listOf(leaf) + intermediates.reversed() + trustAnchors.reversed()
            val validationTime = it.validation_time?.let(Instant::parse) ?: Clock.System.now()

            //TOODO: epired system trust store results in path buildign error
            val context = CertificateValidationContext(
                trustAnchors = setOf(TrustAnchor.Certificate(chain.root)),
                allowIncludedTrustAnchor = true, // default is true, but for the clarity
                expectedEku = it.extended_key_usage.mapNotNull { extendedKeyUsages[it] }.toSet(),
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

    "Validate Attestation Proof With RFC5280 And Custom Rules" {
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
            X509Certificate.decodeFromByteArray(
                Base64.getMimeDecoder()
                    .decode(it)
            )!!
        }

        chain.buildPathAndValidate(
            CertificateValidationContext(
                trustAnchors = setOf(TrustAnchor.Certificate(chain.root)),
            )
        ).isValid shouldBe false

        val customValidatorFactory = ValidatorFactory { context ->
            val validators = ValidatorFactory.RFC5280.run {
                chain.generate(
                    context = context
                )
            }.toMutableList()
            validators.removeAll { it is CertValidityValidator || it is KeyIdentifierValidator || it is TimeValidityValidator }
            validators.add(AttestationTimeValidator())
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

// Example of custom validator, it checks validity only in intermediate certificate
class AttestationTimeValidator : CertificateValidator {

    @ExperimentalPkiApi
    override suspend fun check(
        currCert: X509Certificate,
    ): Set<ObjectIdentifier> {
        if (!currCert.isValidAt(currCert.tbsCertificate.validUntil)) throw InvalidCertificateValidityPeriodException("Certificate is not valid")
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
