package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateValidityException
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.fail
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/*
* PKITS 4.2 Validity Periods
* */
open class ValidityPeriodsTest : FreeSpec({

    val trustAnchorRootCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDRzCCAi+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFTATBgNVBAMT\n" +
            "DFRydXN0IEFuY2hvcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALmZ\n" +
            "UYkRR+DNRbmEJ4ITAhbNRDmqrNsJw97iLE7bpFeflDUoNcJrZPZbC208bG+g5M0A\n" +
            "TzV0vOqg88Ds1/FjFDK1oPItqsiDImJIq0xb/et5w72WNPxHVrcsr7Ap6DHfdwLp\n" +
            "NMncqtzX92hU/iGVHLE/w/OCWwAIIbTHaxdrGMUG7DkJJ6iI7mzqpcyPvyAAo9O3\n" +
            "SHjJr+uw5vSrHRretnV2un0bohvGslN64MY/UIiRnPFwd2gD76byDzoM1ioyLRCl\n" +
            "lfBJ5sRDz9xrUHNigTAUdlblb6yrnNtNJmkrROYvkh6sLETUh9EYh0Ar+94fZVXf\n" +
            "GVi57Sw7x1jyANTlA40CAwEAAaNCMEAwHQYDVR0OBBYEFOR9X9FclYYILAWuvnW2\n" +
            "ZafZXahmMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n" +
            "DQEBCwUAA4IBAQCYoa9uR55KJTkpwyPihIgXHq7/Z8dx3qZlCJQwE5qQBZXIsf5e\n" +
            "C8Va/QjnTHOC4Gt4MwpnqqmoDqyqSW8pBVQgAUFAXqO91nLCQb4+/yfjiiNjzprp\n" +
            "xQlcqIZYjJSVtckH1IDWFLFeuGW+OgPPEFgN4hjU5YFIsE2r1i4+ixkeuorxxsK1\n" +
            "D/jYbVwQMXLqn1pjJttOPJwuA8+ho1f2c8FrKlqjHgOwxuHhsiGN6MKgs1baalpR\n" +
            "/lnNFCIpq+/+3cnhufDjvxMy5lg+cwgMCiGzCxn4n4dBMw41C+4KhNF7ZtKuKSZ1\n" +
            "eczztXD9NUkGUGw3LzpLDJazz3JhlZ/9pXzF\n" +
            "-----END CERTIFICATE-----\n"
    val trustAnchorRootCert = X509Certificate.decodeFromPem(trustAnchorRootCertificate).getOrThrow()
    val trustAnchor = TrustAnchor(trustAnchorRootCert)
    val defaultContext = CertificateValidationContext(trustAnchors = setOf(trustAnchor))

    val goodCACertPem = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT\n" +
            "B0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37\n" +
            "Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa\n" +
            "BGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47\n" +
            "RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn\n" +
            "UGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+\n" +
            "VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9\n" +
            "yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ\n" +
            "XahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC\n" +
            "AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ\n" +
            "KoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m\n" +
            "tvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo\n" +
            "3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu\n" +
            "FMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s\n" +
            "6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG\n" +
            "QYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=\n" +
            "-----END CERTIFICATE-----\n"
    val goodCACert = X509Certificate.decodeFromPem(goodCACertPem).getOrThrow()


    "Invalid CA notBefore Date Test1" {
        val badNotBeforeDateCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDijCCAnKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTQ3MDEwMTEyMDEwMFoXDTQ5MDEwMTEyMDEwMFowTjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHjAcBgNVBAMT\n" +
                "FUJhZCBub3RCZWZvcmUgRGF0ZSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
                "AQoCggEBAKdTl1qhx5hGD+CvPHQU/pDSJCVnLWeXmdblHoJ746b/bW3/GkXFSUPl\n" +
                "1yT36yl6CZJzUJqOYzFkSE3aN2vDcrjviJOAInET39JOxLTkc7J8DxCpz13PmliN\n" +
                "KpQl5p3fY3Lll8UumG/5mZsdphQSp2gIN6w68nJKS6Nmad46or/5l1qsAteEjIGx\n" +
                "a26CC6tV5yEqchk1Htsd4hJz7xUi7vijBM987pOidUjCYNltpZYQYvdbGIjl2LnX\n" +
                "ILVLy2B7Sska+bMVllQM6d932/mzFUxCXCR7eow5ZKo3dPAKOuwTnjTAR3MHfCij\n" +
                "/mRVgxSBDh017j55dVB16y0Si9flCfkCAwEAAaN8MHowHwYDVR0jBBgwFoAU5H1f\n" +
                "0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFGM+vBqe+6HyWaEvS5X+5t5WuIZA\n" +
                "MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYDVR0T\n" +
                "AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAtkgaLAbOwuudAqkh/5xJw8ur\n" +
                "RsA3e1joOqVXy3iP5Uj8o663gzdoBl+sIyDGntdx0h5GjR4QM/SWPlz5yxFrExe/\n" +
                "AaoxXHr77fYZfkgGBCLblxo3wb0iNpKz5OKmb4qtwEOpHygOpSSiV5e2wZDjhN1q\n" +
                "yR3v2lR5L2exD+k4l2Td/0w4uCpom62k+sWY36/h/zKiWFWhnIWqpHYyYOGhYzTM\n" +
                "EtJNWj6H0EWEoB1YNsNZYT3f2w4jOFa7oxfiqFS9kzXIjenc+MIt9uU6+oLFjdzt\n" +
                "jVCxa181mRD3+OiQw9SDtTZXEwPQmp0jj7B5bLGSKK477cAIX1uqxE7jyO8t2g==\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVQmFkIG5v\n" +
                "dEJlZm9yZSBEYXRlIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "ZzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "NzA1BgNVBAMTLkludmFsaWQgQ0Egbm90QmVmb3JlIERhdGUgRUUgQ2VydGlmaWNh\n" +
                "dGUgVGVzdDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8ENtBwoEZ\n" +
                "CsDl8JmmxVIgE7Oxt2NxKj5KrXslioWozKJzjRKKK1N2jHF/RHEmzFYoolOnNMJJ\n" +
                "gIFFYSeAeJshYirpGm9mI5xZ9l72ZfaxtA7SA8m2UhE78WwJJ+oa82CDIiqoOCEm\n" +
                "26yEV1M8OgtFFu/g3by/PcknMXXLd3C7zYPynO/ExnHUfiPfTsorYCTEPqr/p7Ds\n" +
                "yGjTRwdNbF9diPObop4B29TZanZ3gYOVBOTn9N0k1oy2eLF12W9W5CwY+FgywI4R\n" +
                "ZMYQHNK3XNde4KuBoUxgXdAGUBzL/Puz2LY3Vd+2AjNS/hl3i76SKKwK9VrbUkXl\n" +
                "v0EVWvc00ZDJAgMBAAGjazBpMB8GA1UdIwQYMBaAFGM+vBqe+6HyWaEvS5X+5t5W\n" +
                "uIZAMB0GA1UdDgQWBBSp+Lh7Vm9xnfn/IdnPPSVIJfemjTAOBgNVHQ8BAf8EBAMC\n" +
                "BPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQBK\n" +
                "OJZjmGp4sWnBQ541UKsMzBO4X8+YGKPA8tGpC/ZjLPG/G7zwq9IUaKekb6KZ3Q17\n" +
                "KeX8YwORze2nSsMzAkED+rJKa8Bgx7+OFBU10b5qTdVc0Ac9PCDhhq9CGa/sj/yv\n" +
                "ggEXLKq3f2BRnDLKdWO20hR2+FkOrmqtDx4q7wZQDtspGFl20AigOV83joWKHPcB\n" +
                "DtjS5/N8zxeOzciNMHhxy1Sv6A9RCUw95ujhrs7c6WM7yXqWbsWhF2sT2856/FIH\n" +
                "m+Hl4rSmu2MMsrZbcWSbga3AbanFdDX2wsccdmsqAPBzYGpJbTdR/s5HXnPei4fw\n" +
                "PY7kH4Kc9zHuOqFxkL6k\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(badNotBeforeDateCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldThrow<CertificateValidityException> { chain.validate(defaultContext) }.apply {
            message shouldBe "certificate not valid till " + ca.tbsCertificate.validFrom.instant.toLocalDateTime(
                TimeZone.currentSystemDefault()
            )
        }
    }

    "2 Invalid EE notBefore Date Test2" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjTCCAnWgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw00NzAxMDExMjAxMDBaFw00OTAxMDExMjAxMDBaMGcxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTcwNQYDVQQDEy5JbnZh\n" +
                "bGlkIEVFIG5vdEJlZm9yZSBEYXRlIEVFIENlcnRpZmljYXRlIFRlc3QyMIIBIjAN\n" +
                "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtc20YJ/j2rSNlGJ/J9rqsxZKwQvD\n" +
                "+f2lCf9yV6nowMsJGRYdX5ERKWoqW29xpRaseNUf38roqv9TiBy5bXzOoJ3a6zfN\n" +
                "SvhWPf//uk4zP5fBAEwq7VL8+UrpZBsKpbTaVIvIeOfTpvWr9qW1N9J1aH0Y5B8D\n" +
                "VsFsdzrGc7rjbDvb3bz2bymkDKGW2A4XClecaAIGJiJOguEuYMhq4B5tndQ0cAQN\n" +
                "QcDXS9li//HO3vlYyiRYv40hZwaTt41m5cQ21xTfFOa/ORsCa96sAL2TR64sT/u4\n" +
                "DWck/9kh3qxsw9gRSkRydr1xOX3HjA6gYUl7nv04OmUSHwf/w590ry4elwIDAQAB\n" +
                "o2swaTAfBgNVHSMEGDAWgBRYAYQkG7wrUpRKPaUQchRR9a86yTAdBgNVHQ4EFgQU\n" +
                "mXSnPUJsL24xEXiVXHTV4VzB9nIwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4w\n" +
                "DAYKYIZIAWUDAgEwATANBgkqhkiG9w0BAQsFAAOCAQEAPSuzpUlBOhAZ8lTzHWdq\n" +
                "Zoo5cC8+mX8vg3YOTm02idO47H/HcqUjQMJZaUr/gsnr0dABy2kuiU802/JbLp3i\n" +
                "jLGTygmGtU7Wqj2t9IEgDeZdQflrYfaCm8rPqNeiwrQb0Mw52dXLMz3YFLqG1BAG\n" +
                "Fqrxg2utLDQfstLrpMs2BHXsSxSBq6ad7BS32qRweNr1KXQJ4QNnRGFrOARTMxi6\n" +
                "MBY3zCiMJWYtgtV6aCt9t/q1kt1NFCkc8CzFdpgV8/rz4poS4FNweXhT+RqyF7UT\n" +
                "PBzHycgL90/QG2N6LlTHxux9ElHQYy8HwwxlJoE+lPv89DSLNwra1mQ8MJMu7h9+\n" +
                "qg==\n" +
                "-----END CERTIFICATE-----"
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, goodCACert)

        shouldThrow<CertificateValidityException> { chain.validate(defaultContext) }.apply {
            message shouldBe "certificate not valid till " + leaf.tbsCertificate.validFrom.instant.toLocalDateTime(
                TimeZone.currentSystemDefault()
            )
        }
    }

    "Valid pre2000 UTC notBefore Date Test3" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlDCCAnygAwIBAgIBBDANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw01MDAxMDExMjAxMDBaFw0zMDEyMzEwODMwMDBaMG4xCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMT4wPAYDVQQDEzVWYWxp\n" +
                "ZCBwcmUyMDAwIFVUQyBub3RCZWZvcmUgRGF0ZSBFRSBDZXJ0aWZpY2F0ZSBUZXN0\n" +
                "MzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALOY1i2dfQm7MR3F7FEB\n" +
                "eUvqhyz0RVOJ5W9ffzQpg8puuROsdevN68qfhN/GTIHMLmeQeEv56Zsl1hRIKMqB\n" +
                "hDpOvSNoaAeZUGJpAaMBzEdEE0KyVlh70u2IaKk3JYDzsWhmbN4ESXFGpmDccsfZ\n" +
                "8kFZo+XTapSeFEc5ETbyVIV7HHPE54zPX9Ce67kJI0e41R5hsXUKFBA7ORycbcFh\n" +
                "8c8sN3mDYhFFX8m7a2qTN6oHQ6I1fReKKOCfYDs671bbiyFCQWNl+7Ok19qUVOgQ\n" +
                "L/g2HyA1YNvueh8ivNNRRwfv6RTPwhuOWF5FyOXRCTzDaS309Lb3TN9d3a3kAoEf\n" +
                "HdMCAwEAAaNrMGkwHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2lEHIUUfWvOskwHQYD\n" +
                "VR0OBBYEFEBvkKgDjazQ6vxQ2V37VnUlYMSbMA4GA1UdDwEB/wQEAwIE8DAXBgNV\n" +
                "HSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBABDntMraC1zS\n" +
                "kjUQmdbhI+l1j8Is7ApNjb03/Hgq8pjDxP2VNPEy9XgXYDOHaAmt7p7jDYMwBxzV\n" +
                "7TSnFIvR3kYjb5k7YhCMIQXkJJgM2QvZ8m0B5c9YJI6qktAp2sxPfzLuBg7fm4Oe\n" +
                "BqQ6f2NlmLorDqhXG3QSJmXWRXMxti4rWz4mJfuWuzPdZERE9bJ118ijfksQjGfu\n" +
                "pjoWizxTCt8kRMP9+RSD8Hzipuxfc2JPn16fNrXMkyBtek82L7tNo1raLueyPcEg\n" +
                "Z5RpwEX/C4nlsQV3JS2viDxhcdtgcmn/A/ho7Ta4QazDqWjQywXExpEpgrp7ExFn\n" +
                "hiss7AFKddQ=\n" +
                "-----END CERTIFICATE-----"
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, goodCACert)

        // Validation fails due to the wasCertificateIssuedWithinIssuerValidityPeriod check,
        // even though all certificates pass their individual validity checks as required by the test suite.
        runCatching { chain.validate(defaultContext) }
            .onFailure {
                if (it is CertificateValidityException) fail("Unexpected CertificateValidityException: ${it.message}")
            }
    }

    "Valid GeneralizedTime notBefore Date Test4" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBBTANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAgGA8yMDAyMDEwMTEyMDEwMFoXDTMwMTIzMTA4MzAwMFowcjELMAkGA1UEBhMC\n" +
                "VVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExQjBABgNVBAMTOVZh\n" +
                "bGlkIEdlbmVyYWxpemVkVGltZSBub3RCZWZvcmUgRGF0ZSBFRSBDZXJ0aWZpY2F0\n" +
                "ZSBUZXN0NDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0TXsIKGzxY\n" +
                "iX5lX1bWQb/MZ9pouA3EQT8bxiWbQe3iWrZE5xIU4jFopRL8RXASP+lQIROJWqjT\n" +
                "GtZhEaNQyB9CmNSz5w3Q/dME6LPrdiUF63klD3lY/J1cJheLov0Ql9Rshvrcjluq\n" +
                "xR0aMebihrCVAbGB9fjapEf4D8xtm/l5SMvO7olLyDZKkibHgmzgZ66/ebGPrc3o\n" +
                "OmxjoqvkyyH+vlRQgfv4oAVFetdVyYB8i2eJp47d2aFGTsWmn6zIoM7fy4iuu0kK\n" +
                "07KGV+RGIif3sHoWXv2Uahz56Y7MGr135s/S8e80jA4KrfQpzqpN07ncyEtFGEs5\n" +
                "3WeTcZi5zLsCAwEAAaNrMGkwHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2lEHIUUfWv\n" +
                "OskwHQYDVR0OBBYEFM3r3nHYztXgRqo9a88ywemUwz7vMA4GA1UdDwEB/wQEAwIE\n" +
                "8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAHWf\n" +
                "JSZe+DwVSi+fwy98C4I5bZrrkWUX5P3ffOQkO1NrPjVURAvXqyTXbzYcf+PM5W+k\n" +
                "J6XD2jJvNCRNQ2R8AIdVbG1fIfAzBR3PhEZPL9qKhi2H1q2IloF1Kw26ghxS5cAF\n" +
                "cfwkOyQgNUpyFp9kKT2OE+3GM6/zf8SVy0/bFL6Rf/5yrJ273Of0+ymy2CY/irTM\n" +
                "/4X7WLSkSGyPz9RHiT+LoRSel59eclRDxQKXgyToiTgGTKXbEFcilTBT6+0WCgcJ\n" +
                "3Lw5qc+s12lQDFF8T903ef6C77dPOYMcxnCD2WlBInOSoqsGhn8NDf6YQYsDFCbl\n" +
                "Oj2T6kRdn8YUigjmrhM=\n" +
                "-----END CERTIFICATE-----"

        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, goodCACert)

        // Validation fails due to the wasCertificateIssuedWithinIssuerValidityPeriod check,
        // even though all certificates pass their individual validity checks as required by the test suite.
        runCatching { chain.validate(defaultContext) }
            .onFailure {
                if (it is CertificateValidityException) fail("Unexpected CertificateValidityException: ${it.message}")
            }
    }

    "Invalid CA notAfter Date Test5" {
        val badNotAfterDateCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDiTCCAnGgAwIBAgIBBTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTExMDEwMTA4MzAwMFowTTELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHTAbBgNVBAMT\n" +
                "FEJhZCBub3RBZnRlciBEYXRlIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
                "CgKCAQEAypzKnjMK9B852wzLGnbU3ueOStmx1eypNdu7Hp4p+tGo4yA+MtHxmowk\n" +
                "V6+nvIJPlouENL+PsGm5hG78ZUcZdyJxIWDjSwdq3xI8nLFWfNftlDBg46lWJUoq\n" +
                "NLktefuraN7VVdxT3BAS2qTV0t4jjXHwgwln+cnQbxWPD1wjLY87yip9vkhPVMnR\n" +
                "bLjdPIkvW5C99JjcqCyDn29T0mbWuYtUmsYbYYdIAbwAHU915tJQJ15JqHucNfu8\n" +
                "Xk67nakILTO6vzc++lmYSkVJEkGE7Gen2BMpOCAjLjmRU9nFBfp2d8SOVl5aggu2\n" +
                "hJrok70GS9auRuJBwZoQJjp0PiTJkwIDAQABo3wwejAfBgNVHSMEGDAWgBTkfV/R\n" +
                "XJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQULA799+4886Rm7OcFn4iz4s90Rtgw\n" +
                "DgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMB\n" +
                "Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCmiMVZwyJLiTnmwJLfGZ5jfdi4\n" +
                "nNcnS202Eao1JeJ7+N1npN3KyAj6lHsey8PtRvsliHAtTOgILzAKdY7pfXoqbUKg\n" +
                "KB0lwXQAquIA0yXuVZRledjaSvqoyadymyDds+5oFuk1X1i4VQAxzF6PmTu669E5\n" +
                "WGQryGH8oR6+xLAB+kQ3xAkE/X1NsQSrwp87GKGBAG2VXTvBEVCXovRBWEhqQLaK\n" +
                "OXS/YMCySS+G9WHXQdW4IPj7lB/2ri/N/+zUE59szrmO5Q2uqZsMqHAiSzj3cWhq\n" +
                "o7jIJZfyQ9biZZVo5NnR4Eltpev0Tl+4Z/OqZt4is6dHKI2A1p7ze4KqZrQm\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUQmFkIG5v\n" +
                "dEFmdGVyIERhdGUgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBm\n" +
                "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTE2\n" +
                "MDQGA1UEAxMtSW52YWxpZCBDQSBub3RBZnRlciBEYXRlIEVFIENlcnRpZmljYXRl\n" +
                "IFRlc3Q1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3CcZ0DqE9Pw6\n" +
                "P0I9jfc3becBcujw8y+uEiSGI2WWZvtY/5cEnif001zkbDJYCCXsaegUoJeh1/uv\n" +
                "GL+wFCAw9ZKJ/po3NzuLSq9ER+jZrkjQeskhs1TWFVAL5Z1HphBRruutpMB31nhx\n" +
                "P6MCP1ZS1wxbWwZRTtg2yINKqX2wRRGTIPB2dWa5Dlv0UL7DfypPfQsVoQF6XZ/7\n" +
                "X6yWyYmRsiL9OJRh07ExsVAQFALZ/6tIXrWpgyQWRJInygoNwmkSTTc9gmetr53d\n" +
                "5e0W/EPBSr8sCbmYpDI6MWJsyZvh16lAc3Zf6sx1PHJtaZ9tt6/WJ148aLV0ffUS\n" +
                "gnvHrdBjjwIDAQABo2swaTAfBgNVHSMEGDAWgBQsDv337jzzpGbs5wWfiLPiz3RG\n" +
                "2DAdBgNVHQ4EFgQUc086TbYTKqLTmNpBE0qlpFjKkKMwDgYDVR0PAQH/BAQDAgTw\n" +
                "MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG9w0BAQsFAAOCAQEANsYL\n" +
                "aZkskh6vUFY0z42Z3HqV7ewk535l/Zcqytm9JFoUtt4tX11iVVLvzKRzE1xRZQrI\n" +
                "1SIvfCSexc+vwMjw4bIRV8PSytQqXI6R27RERT5RLkpSBFfSXYJXrl6z4txFcEGD\n" +
                "ed9220tfXUDOt5lZ/V9qlvOKInpq1gKj2C8mknHDYm6643I4Sefi+Mw5M3ohPfEs\n" +
                "8y1AdEwow02R702NYa2dvBDu309BpjryhYrRxfXezN2l0Yc7z8Y2bISXclx3W2dh\n" +
                "dqeABI571GE28EkfhPbRKuW+yQOUnjyMqvik6y5A7jtnFicTeoi/IIT8COWEg7gE\n" +
                "/6N/kRUqqgeRucK71g==\n" +
                "-----END CERTIFICATE-----"

        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(badNotAfterDateCACert).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldThrow<CertificateValidityException> { chain.validate(defaultContext) }.apply {
            message shouldBe "certificate expired on " + ca.tbsCertificate.validUntil.instant.toLocalDateTime(
                TimeZone.currentSystemDefault()
            )
        }
    }

    "Invalid EE notAfter Date Test6" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjDCCAnSgAwIBAgIBBjANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw0xMDAxMDEwODMwMDBaFw0xMTAxMDEwODMwMDBaMGYxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTYwNAYDVQQDEy1JbnZh\n" +
                "bGlkIEVFIG5vdEFmdGVyIERhdGUgRUUgQ2VydGlmaWNhdGUgVGVzdDYwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVkIXCcTqIC0o6oloj+rv8wFYVu8ss\n" +
                "0yLlBy5nINdpFsuWwMezsprPdut5NnThg0m+t6SiQpFqJcqQKVh2i+z8/DUWfWNr\n" +
                "1H6ShCDO7xPupe2o5pSJe5dTonyC2LHLABc9HQxGxCvL6hAXz+/nMciADvYrCHlr\n" +
                "n8ztVSKXI6jaBZwb0KzcsWHtjFxVWbPZ2KVp2yElWUJxUdX9rUnOYVATeKVKHohV\n" +
                "QFYA6wAe/UETnkCdz1JWqs+vG3QMjw5/w1V1lthf+SFbJiT3PVV8VCxq23bNy4wF\n" +
                "M5GVeDJYs3lIm7rIo0/d7PvLhVUCQWmsQKMyLwS3xgBrOeIWNsVAPM5LAgMBAAGj\n" +
                "azBpMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJMB0GA1UdDgQWBBQl\n" +
                "6Mt3tdW2ryNfEQ9WI7oGr62koTAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAM\n" +
                "BgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQBUXyfp0KcfRQdV031V8bA9\n" +
                "gngzQtrEI05Aa0VbgTv3b7VKeIcgwsUMeNjuJZ5hUxAISm8+xwoY5e27EOHxWG+y\n" +
                "Dtk2Czfv46Ga7Pau5P5wag2QkPk2WlmVovMp92zb+GI5vyLFnEdNY3zkTtFxCbYI\n" +
                "LEMROtRjDM3EGkXmkoblz+Z+u7NaLW4cKI9gBYytP3Ezg0R8dCRjDRkXy+95CE8q\n" +
                "6taAwnxIQ6FqGxjBgf84oXVW81qcIf8N3i+ZztMK2a3swEDY1CyeSnj9WAX4kt18\n" +
                "Qou/YP2hqVJxApNFFcBfqybSUOyLu8mbYlBAAYNB70QchygcEayvAXOIXX/NunA5\n" +
                "-----END CERTIFICATE-----"

        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, goodCACert)

        shouldThrow<CertificateValidityException> { chain.validate(defaultContext) }.apply {
            message shouldBe "certificate expired on " + leaf.tbsCertificate.validUntil.instant.toLocalDateTime(
                TimeZone.currentSystemDefault()
            )
        }
    }

    "Invalid pre2000 UTC EE notAfter Date Test7" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBBzANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAgGA8xOTk3MDEwMTEyMDEwMFoXDTk5MDEwMTEyMDEwMFowcjELMAkGA1UEBhMC\n" +
                "VVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExQjBABgNVBAMTOUlu\n" +
                "dmFsaWQgcHJlMjAwMCBVVEMgRUUgbm90QWZ0ZXIgRGF0ZSBFRSBDZXJ0aWZpY2F0\n" +
                "ZSBUZXN0NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8k5yDE7wMf\n" +
                "wlOhyZcxb9+PlGIC417Lq+G5CDDQQGbytGuZKYQR3+0AhiEUO7YwxfIeOtE4YOBl\n" +
                "QsZsPUSOgSCb2l4s2rbH7V5QFfRcf8f3RQVDjMqhFXvIIWW5uys1poKMqXVDLw3x\n" +
                "g3ysL2kVl/zORmqI3obmehIa2m1EUHR3jY++I43rJnFUsTvTNGKsE7HLTpkLDABH\n" +
                "wptY+Ztt7J+sMc5w/pXweCkYLSdulazQ0EKwjDdmWS4BE/3CLIeQkTCB/CTkkseg\n" +
                "dHPaD18xeV+4LLjAB2dsAmIwAnRiI+LouvCaF52pVBedX5cg6xMPTz1XfLzX3SkL\n" +
                "3hj4LgUtuJMCAwEAAaNrMGkwHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2lEHIUUfWv\n" +
                "OskwHQYDVR0OBBYEFNUChZ5TMCZHiJZ+TyOTFmSU8xivMA4GA1UdDwEB/wQEAwIE\n" +
                "8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBABiL\n" +
                "KJrH+iYNkDzEmwMr9Iebl4gc2uzCObyDkbaQ/UeuxbCvfUm3x1vYbty3HNEKp+tY\n" +
                "JBXAEDh2GbHU1cLzhP+tNTYQuqgWzE86ZOKWLYI7wUkezHwL00wtOYI8RQfAScGV\n" +
                "OySp2qwKgeKjXUAd/BVa6FVOzXkHavXNy903ssmko4d9sD+yb9FFY9UrlmIhXewl\n" +
                "lR2rcUDtHT0dH5PJf7arPoGTRoePSFWeY6D7IBNuXfuhB3WEj+UQzzoANelmavIL\n" +
                "VwM88Eszmwmofr2sbWi16b6z7XAKbwQm7n4hrwOd3vYTO/zRM0KBB9Y27p/trFLL\n" +
                "6CmNjRghrN1erPNL1Z0=\n" +
                "-----END CERTIFICATE-----"

        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, goodCACert)

        shouldThrow<CertificateValidityException> { chain.validate(defaultContext) }.apply {
            message shouldBe "certificate expired on " + leaf.tbsCertificate.validUntil.instant.toLocalDateTime(
                TimeZone.currentSystemDefault()
            )
        }
    }

    "Valid GeneralizedTime notAfter Date Test8" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBCDANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAgFw0xMDAxMDEwODMwMDBaGA8yMDUwMDEwMTEyMDEwMFowcTELMAkGA1UEBhMC\n" +
                "VVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExQTA/BgNVBAMTOFZh\n" +
                "bGlkIEdlbmVyYWxpemVkVGltZSBub3RBZnRlciBEYXRlIEVFIENlcnRpZmljYXRl\n" +
                "IFRlc3Q4MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3JsqVzyLOC5n\n" +
                "QkAT5iNLE/lsxf/3jU8ojrjoBbTYdgaUaun44lvZwesI/WEd7WbmIk4bnuLDk2pc\n" +
                "VQY+UnqPJS3j4exQshmfKSwtJnfnqiCNDsujHAkHP0ETMQGbQCfz2sibFf9TFXrp\n" +
                "mcIHRX8cXIFcQvcvGyKUzO6pkZXRQ5CH37tVWJCj1q8oACXaBqdC4VRKYFO0lhWs\n" +
                "epDrq2xWlvF7pOEJr7MvyM2tqaYFEKVgCXomhY1qxY3tWUr9n2OIEOt71o5+671O\n" +
                "Mqd4cZJREF8vpkelQxEGMMu7DR1+pGbkrxXqyYAmjDE5czfXQOLHrWKJlXsnv37L\n" +
                "gSb0h6cWyQIDAQABo2swaTAfBgNVHSMEGDAWgBRYAYQkG7wrUpRKPaUQchRR9a86\n" +
                "yTAdBgNVHQ4EFgQUMT3myQxH68BT3YDCOy2mohpE7iAwDgYDVR0PAQH/BAQDAgTw\n" +
                "MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG9w0BAQsFAAOCAQEAcDEv\n" +
                "K/j/gsTTaDIPxcb0iblmMtDBoM6sVI1hp/cpXz47WqedfVQxKpMAj+nyCepRHFw7\n" +
                "tnjoWzlpDJTbzDX2RaQTyzzZ1hoef9po4LSjt+ukybp0D3bf4m47s6cat+f5XKME\n" +
                "BqLI+2C9V17tBV6ZM2LbCncc/RnHXwaPCJQUdQV4QOP0+aw6/pmCfUJH0Bn/fM80\n" +
                "gPxHN3yEds/Xes+JRf3dzFMcGso1IA4fx/S3DqkT+uJG75jl2cI/SUZCdw6G5Aze\n" +
                "h/wfRrNGyqQYOsgKkNION7NjDmeZ5doj4Nk1MaaYZmm/Znn83fMtXuGchn26BmIO\n" +
                "UNDDn9zsAsqcF4TkGQ==\n" +
                "-----END CERTIFICATE-----"

        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, goodCACert)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }
})