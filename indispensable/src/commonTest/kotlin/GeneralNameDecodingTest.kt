package at.asitplus.signum
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

@OptIn(ExperimentalPkiApi::class)
open class GeneralNameDecodingTest : FreeSpec({

    "Alternative Names Decoding" {
        val sanRFC822namesPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDDjCCAfagAwIBAgITBmkNiyOeghKn10MwmYC7ggPHDjANBgkqhkiG9w0BAQUF\n" +
                "ADAPMQ0wCwYDVQQKDARQeUNBMB4XDTE1MDQyMDEzMzgxOFoXDTE2MDQxOTEzMzgx\n" +
                "OFowDzENMAsGA1UECgwEUHlDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBALKXpkqcSgZeT5NpvKzMdbVy2zJZUaCqF6ghWHAEhebCl9FgS7CY/RcBjZj2\n" +
                "lPS6Xep614zDQbV17q2WliZNJH7s3Q3tq7mhlYDsScd5cZPyM/p+0dCzVTeUp0NE\n" +
                "636TDzobcqRk6qWT53vBgvWvS3RF4UfanUB+l6KwsD0YXOX82TmHIzX2CQApD9m7\n" +
                "rTPvB4L5hbqo2lwlHzRZM3Ejh0X5vazBKU4nADS/ePY7KQjGM/UUD37Sm7ApxQa3\n" +
                "EaMx+QQvmWHC/J53wY1fOAAWj60baZ6+24/GZJzThXPdcFIB5Jh6+iFoPUr/iF8R\n" +
                "N54C7pZJ3G1wV37zp1Dv/32FPqkCAwEAAaNjMGEwXwYDVR0RBFgwVoEFZW1haWyB\n" +
                "DWVtYWlsIDxlbWFpbD6BE2VtYWlsIDxlbWFpbEBlbWFpbD6BH2VtYWlsIDxlbWFp\n" +
                "bEB4bi0tZW1sLXZsYTRjLmNvbT6BCG15ZW1haWw6MA0GCSqGSIb3DQEBBQUAA4IB\n" +
                "AQCeV4X93YQMWRZpSUdxDSFUpu3GOXvJeDB+rUWnTEoRohjWU3QO8qOVqS+WqkP1\n" +
                "EkYSTJc4bs50NCIK8QS1LJPt3jMfYDiVW0WP4sV57XzoLE6qtuaTKn0oAqz5Vn9c\n" +
                "5LG5MTPcYlDEuGQet4DvqtF+oAqjOeAm/rELW22K/JxAR6nZT3wnH5WyaK7nQItR\n" +
                "LFarWRraA8q8sIOVs1HR+vubEYk/5u6n3AXmzxZztWLp5Ow0/8x6XU/IwJlqg+rj\n" +
                "fDJeYJCW8p8G/lStcKSPsBvJC45fZFFI2oOUNs0J+FsKoCihzN3ShbirxMbMY+Hy\n" +
                "ZLL0a0t1JexOoqEvUORZXAFL\n" +
                "-----END CERTIFICATE-----"

        var cert = X509Certificate.decodeFromPem(sanRFC822namesPem).getOrThrow()
        var generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.size shouldBe 5
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.RFC822 }

        val sanEmailDnsIpDirnameUriPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDeTCCAmGgAwIBAgITBmaVCZDdiLn35OlG4nYY3u8VXDANBgkqhkiG9w0BAQUF\n" +
                "ADAmMQ0wCwYDVQQKDARQeUNBMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwHhcNMTUw\n" +
                "MzI2MTU0NjMxWhcNMTYwMzI1MTU0NjMxWjAmMQ0wCwYDVQQKDARQeUNBMRUwEwYD\n" +
                "VQQDDAxjcnlwdG9ncmFwaHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQC7jXYLOkxgQzNOcpuenV1hbxRxAPds6rAThGB8MQMot1fZbyHzVmYtRGiGdcGg\n" +
                "TolQDp38IF43B/e+IzG/zpYpLOHijSI9dGXKYb0s7XCProvS7OdnvMtJpi4p4jhe\n" +
                "qeQEETHkoOo7I/B9StpPvcvHq3lteMFZgS+Sx4UhKEWsd42uNOjL0QQvdoNqAJI1\n" +
                "srDiP+mqhCtTvubOJjOSZPP4dxganQbSZ2i0wJYBwo1YYFU3x9b2UHmmuVNi0kqj\n" +
                "3fYkFEr6JmLJ/FalYPEc2ffs4ukSWCxwHGnbGvLt1LeteaufIWHiekuAEBkogtu3\n" +
                "w4EKQUHGwkRv8gWyPG/jINPXAgMBAAGjgZ8wgZwwgZkGA1UdEQSBkTCBjoEUdXNl\n" +
                "ckBjcnlwdG9ncmFwaHkuaW+CD2NyeXB0b2dyYXBoeS5pb4cEfwAAAYcQAP8AAAAA\n" +
                "AAAAAAAAAAAAAKQ0MDIxDjAMBgNVBAMMBWRpckNOMSAwHgYDVQQKDBdDcnlwdG9n\n" +
                "cmFwaGljIEF1dGhvcml0eYYXaHR0cHM6Ly9jcnlwdG9ncmFwaHkuaW8wDQYJKoZI\n" +
                "hvcNAQEFBQADggEBABpsK+icD/vLFrdzbg/qJghZ+DqAx4u8e3LmBQLKMgegrWhC\n" +
                "wcXgqeG1m9BmasZv3UjS9v0oiwOQCmewopm7Q2F/IOzEqYmIoo56Y9//dou8+yvB\n" +
                "10EA9Lu3k1aRQa2mAG83dGovPTEtbvdsMLhVP3udA5rADEPP4KC736/NrpPLj4pE\n" +
                "thxhh0QJbGLQ9HouS6ic9WjYDhqxn6XJrOWSJSeRsVXn4AKAiYsQGNnSJGRZtjqN\n" +
                "q24kUsuB7cAQSjWPKETl/UxTXTwhlStLg/s1aePRsOXromlCPEgRh+Noe/V7jFEG\n" +
                "Hcbr0ocG/LezIT0EPOx1gErTQo6R9Rp+2DJEBFQ=\n" +
                "-----END CERTIFICATE-----"

        cert = shouldNotThrowAny {
            X509Certificate.decodeFromPem(sanEmailDnsIpDirnameUriPem).getOrThrow()
        }
        println(cert.tbsCertificate.subjectAlternativeNames)

        cert.tbsCertificate.subjectAlternativeNames?.generalNames?.size shouldBe 6

        val sanOtherName = "-----BEGIN CERTIFICATE-----\n" +
                "MIIC/DCCAeSgAwIBAgITBmaU4PsnM8bqyYetOWyVgmVRkzANBgkqhkiG9w0BAQUF\n" +
                "ADAmMQ0wCwYDVQQKDARQeUNBMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwHhcNMTUw\n" +
                "MzI2MTUzNzMxWhcNMTYwMzI1MTUzNzMxWjAmMQ0wCwYDVQQKDARQeUNBMRUwEwYD\n" +
                "VQQDDAxjcnlwdG9ncmFwaHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQC7jXYLOkxgQzNOcpuenV1hbxRxAPds6rAThGB8MQMot1fZbyHzVmYtRGiGdcGg\n" +
                "TolQDp38IF43B/e+IzG/zpYpLOHijSI9dGXKYb0s7XCProvS7OdnvMtJpi4p4jhe\n" +
                "qeQEETHkoOo7I/B9StpPvcvHq3lteMFZgS+Sx4UhKEWsd42uNOjL0QQvdoNqAJI1\n" +
                "srDiP+mqhCtTvubOJjOSZPP4dxganQbSZ2i0wJYBwo1YYFU3x9b2UHmmuVNi0kqj\n" +
                "3fYkFEr6JmLJ/FalYPEc2ffs4ukSWCxwHGnbGvLt1LeteaufIWHiekuAEBkogtu3\n" +
                "w4EKQUHGwkRv8gWyPG/jINPXAgMBAAGjIzAhMB8GA1UdEQQYMBagFAYDKgMEoA0W\n" +
                "C0hlbGxvIFdvcmxkMA0GCSqGSIb3DQEBBQUAA4IBAQBFZHNeysAOnKD5Wq0vtZiw\n" +
                "tfSJnbuxk4pqjvudSz2pH9abMgrfddlR0Zhb4VJx7+4DMGCNLhZHjNQhks670QZY\n" +
                "MRq/x8Yk38pCVrF6pce87GHQSMdQ09GyknKakw0roN0iMzDy50RGiv+MXnjbiyjB\n" +
                "lgqbs4rMoUI1CRTkid8yHuh+QUMETuQ17gKBCz+JdS12743ziZSNdjf9WKNzCEH8\n" +
                "6YAFJUmu0xyVG1Rf1dgek/miLtB6sqUOAiC4IlTFCXu+c6UHd+d0OIZnaLNWiMDr\n" +
                "+5nh4BPuL/buvsLb0SOoKbnHZZYyBKFcdIf6iejsHpZ0lYmeBRqf0HlLUva1zWoM\n" +
                "-----END CERTIFICATE-----"

        cert = X509Certificate.decodeFromPem(sanOtherName).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.size shouldBe 1
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.OTHER }

        val sanRegisteredIdPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIICsjCCAhugAwIBAgIBADANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJVUzEO\n" +
                "MAwGA1UECBMFVGV4YXMxDzANBgNVBAcTBkF1c3RpbjENMAsGA1UEChMEUHlDQTET\n" +
                "MBEGA1UEAxMKcmFuZG8gcm9vdDAeFw0xNTAzMjcxNTEzNTRaFw0xNjAzMjYxNTEz\n" +
                "NTRaMDsxDTALBgNVBAMTBGxlYWYxDjAMBgNVBAgTBVRleGFzMQswCQYDVQQGEwJV\n" +
                "UzENMAsGA1UEChMEUHlDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtrm+\n" +
                "lMamYGVuULhG2m7HjsNz48bV9/9GShnLW1C7jajVbOu5YetyVfyKXoymbqT68O0d\n" +
                "7YxnFz1Yiik3/RqxbTL8ccc2F5VXXcwzc5A6EwtqJNVCG3NY/Ft5vYONVl20dyhV\n" +
                "/7BzKA/Lv45FnSDyiGss/amNGodznEk/95QdeLkCAwEAAaOBrjCBqzAJBgNVHRME\n" +
                "AjAAMB0GA1UdDgQWBBTnx8+v+mXQU9rQzOr3cgKfLE8UbDAfBgNVHSMEGDAWgBQK\n" +
                "I5A8UXeub7z+dqK+7W7RQp2ntjALBgNVHQ8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB\n" +
                "BQUHAwEwLAYDVR0fBCUwIzAhoB+gHYYbaHR0cDovL3BhdGgudG8uY3JsL215Y2Eu\n" +
                "Y3JsMA4GA1UdEQQHMAWIAyoDBDANBgkqhkiG9w0BAQUFAAOBgQBiOICo0oe0ndcE\n" +
                "+/QAV+rIMoDP5WeMw6/9o2r7sGTGJPmlMScef1+rSkdufv3SqehjWo8HYTF83BgD\n" +
                "rwBtc1eU76bb3W7hhPv8pTAiQNsyYMDv2MKLMkL7UvKF+55acMGt/nJRN9zxdnIG\n" +
                "ZuIUw9ZOtEByVZgu6BY0xseGOTEhvA==\n" +
                "-----END CERTIFICATE-----"

        cert = X509Certificate.decodeFromPem(sanRegisteredIdPem).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.size shouldBe 1
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.OID }

        val sanWildcardIdnaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIC5DCCAcygAwIBAgITBm+2/ut33Rv56bgfggfOb0a2uzANBgkqhkiG9w0BAQsF\n" +
                "ADAXMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwHhcNMTUwNjI2MTc0MDUxWhcNMTYw\n" +
                "NjI1MTc0MDUxWjAXMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQCylTa0WkLvIXB4sWoPdv5iL3idlVHKR+ncODKL\n" +
                "nwQ2Jtd990MfakOFRLrJFF1tfPL4qyRbbyMyrgCOoKBCAuIdBZfBDH3JWFjxGy8J\n" +
                "Yls8yVeAVKreV18HmLvAsBL3bnr7Gk3vpznrfoG5rn5T/fL0cqqTXFV8zQhjHiEo\n" +
                "zftSaoq0LOxsSgFdxXS8e8K6RMvLCZPcMpI4fo1Kq2QBT2J1x1/Hq/VnK132cs0g\n" +
                "TOyiTyyJfvRmlqdXowh7Jf8LQB4mM6gc023fEdQ+HH6JYX1vDQVxaiTM6KMYJNv/\n" +
                "l4gchP3jknOfZffwGGdXQrtUMhQmltnSqV5nY/G2OGm/Z0pdAgMBAAGjKTAnMCUG\n" +
                "A1UdEQQeMByCGioueG4tLTgwYXRvMmMuY3J5cHRvZ3JhcGh5MA0GCSqGSIb3DQEB\n" +
                "CwUAA4IBAQCLU5fYLcj+Y2XMtYdJY0nGPoqXNV4VyBDXiJnhwuAvwSkOaw16wPEy\n" +
                "hwfIwoX11zA4FwV1TqgULaPc+jEuIBT6zjqBCoeDXqV6m2JGHhGuO1+93zZcrSVu\n" +
                "PJh64XtyWNfcHzca7HDblHJb7t9PaDrYc7fK1rvhYOyZ9X7wXMxsstsVPPQhDKB1\n" +
                "pY7m/Txh7qvbcghHBH4IVl+5wVp8Cpoahgc3r99L84wyQj3i/NLBbkr2FSjrlzBV\n" +
                "y8yxbrI+KusEVq6eAo/xWN4aT9MxG3ZfxOYoajKotXurp1yhTBWNV8Lw8S0T5UWn\n" +
                "AI2linN6ki9dRgpCZ0/74PlKkMcV9bdu\n" +
                "-----END CERTIFICATE-----"
        cert = X509Certificate.decodeFromPem(sanWildcardIdnaPem).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.size shouldBe 1
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.DNS }

        val sanIdnaNamesPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDGDCCAgCgAwIBAgITBmkKn/MvOUXQk1/lN2si9LdhbTANBgkqhkiG9w0BAQUF\n" +
                "ADAPMQ0wCwYDVQQKDARQeUNBMB4XDTE1MDQyMDEwNTI0NloXDTE2MDQxOTEwNTI0\n" +
                "NlowDzENMAsGA1UECgwEUHlDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBALKXpkqcSgZeT5NpvKzMdbVy2zJZUaCqF6ghWHAEhebCl9FgS7CY/RcBjZj2\n" +
                "lPS6Xep614zDQbV17q2WliZNJH7s3Q3tq7mhlYDsScd5cZPyM/p+0dCzVTeUp0NE\n" +
                "636TDzobcqRk6qWT53vBgvWvS3RF4UfanUB+l6KwsD0YXOX82TmHIzX2CQApD9m7\n" +
                "rTPvB4L5hbqo2lwlHzRZM3Ejh0X5vazBKU4nADS/ePY7KQjGM/UUD37Sm7ApxQa3\n" +
                "EaMx+QQvmWHC/J53wY1fOAAWj60baZ6+24/GZJzThXPdcFIB5Jh6+iFoPUr/iF8R\n" +
                "N54C7pZJ3G1wV37zp1Dv/32FPqkCAwEAAaNtMGswaQYDVR0RBGIwYIEeZW1haWxA\n" +
                "eG4tLTgwYXRvMmMuY3J5cHRvZ3JhcGh5ghh4bi0tODBhdG8yYy5jcnlwdG9ncmFw\n" +
                "aHmGJGh0dHBzOi8vd3d3LnhuLS04MGF0bzJjLmNyeXB0b2dyYXBoeTANBgkqhkiG\n" +
                "9w0BAQUFAAOCAQEAHovYDe4tb+/fHOtOgskw0iyXmVLFrZ6Y6Yng5PKFaWIKd9ew\n" +
                "dkErdNs9ZcQwo+SFdql2pxOCb6sHxo9XukVIHZZzr3so8so18c5f2TaZKzYL0bzv\n" +
                "znfINwkSbF80seuW/dsR+4wGvtEz5ox/96MkTsnP3tFjNS+2zF9ghtTg/XABtNBD\n" +
                "dCDIeD0fX4zEdMKb2tME1lsyra7fy6K1ZOYW+NefCABNer59SON+G8a0DzkaB6DO\n" +
                "jT8yAu85NvHtnHXYGl4nsE7/HndFZSU8GQHYsTAr1kJUfU3CZfoLSRvjlHnNFwWn\n" +
                "ddn9wNOpNYiILGwg1FFtGUuqi9z/rZb3zZlA3g==\n" +
                "-----END CERTIFICATE-----"
        cert = X509Certificate.decodeFromPem(sanIdnaNamesPem).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.count { it.name.type == GeneralNameOption.NameType.DNS } shouldBe 1
        generalNames?.count { it.name.type == GeneralNameOption.NameType.RFC822 } shouldBe 1
        generalNames?.count { it.name.type == GeneralNameOption.NameType.URI } shouldBe 1

        val sanIdna2003DNSPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIICyjCCAbKgAwIBAgITBmuEOcehqQ0T8RSnZfjR7vyzcTANBgkqhkiG9w0BAQUF\n" +
                "ADASMRAwDgYDVQQDDAdQeUNBIENBMB4XDTE1MDUxNTA5NDYzOFoXDTE2MDUxNDA5\n" +
                "NDYzOFowEjEQMA4GA1UEAwwHUHlDQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                "ADCCAQoCggEBAKILkg/zRXCemIUAy9NxKfLkiP640nVLEHOyQagPtWacyu4VS56s\n" +
                "lozj4SFybkz3sZMid/agQagM7JhnXer+6j4BL/76KM74RSf1onb6AnRYb3Mo0nIz\n" +
                "l1dT5w4fRGgbpoW+Z+GjuQnlwVteIvg0/V6uqETp1T9tYkpv+SJKlJJ2TtNHz6Fv\n" +
                "AOcJcqagnKmbOTyMuk5vog83/nVVm2fEPOaKYrjUymgmfiWCXrMD/US5bUq1+Hr1\n" +
                "10m8D8vhyaQhxSsX2Z+v63PhWrybJLUFHfmw7G4c6jM2Ojv9/Mbuh+UmEm0SFvZf\n" +
                "Ltq8ts5chqpAAsdaYYuUOEbGpHeuCtsH2c0CAwEAAaMZMBcwFQYDVR0RBA4wDIIK\n" +
                "eG4tLWs0aC53czANBgkqhkiG9w0BAQUFAAOCAQEAAylbqwHOUkqkWJ1USyIoPjra\n" +
                "Si2O3XmQ2h7BSDeTP7hi8bHeKisjdGX5RlZvuQb/VCEnLpnQeyo0jP8rVoGX+hl/\n" +
                "LAqpTWQhXQYAfCfWHENs0f+HJw0VB/I7/K6JfQfgZKhfaG7Lb3ZUYN6weM+DDS7E\n" +
                "cUbmnk4fAyPLBTPR4nOw0hWF1IhqZ4x9Vr6s1VlmEaQ/sJi3zhFQx2mb8Lb/3h9b\n" +
                "/WvYRvniEUYxGZ/q1fRmf+gGIacVTJtzpTxSDdSJugfhbm2wRQaXlSojRL+wO5Kg\n" +
                "rDGwi9y5y+zWOFtQQCDEdhFLsw0ae3HPBQxxv85PzpuQD3EDgO0UolhAdZlIZg==\n" +
                "-----END CERTIFICATE-----"
        cert = X509Certificate.decodeFromPem(sanIdna2003DNSPem).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.size shouldBe 1
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.DNS }

        val sanRFC822NamesPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDDjCCAfagAwIBAgITBmkNiyOeghKn10MwmYC7ggPHDjANBgkqhkiG9w0BAQUF\n" +
                "ADAPMQ0wCwYDVQQKDARQeUNBMB4XDTE1MDQyMDEzMzgxOFoXDTE2MDQxOTEzMzgx\n" +
                "OFowDzENMAsGA1UECgwEUHlDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBALKXpkqcSgZeT5NpvKzMdbVy2zJZUaCqF6ghWHAEhebCl9FgS7CY/RcBjZj2\n" +
                "lPS6Xep614zDQbV17q2WliZNJH7s3Q3tq7mhlYDsScd5cZPyM/p+0dCzVTeUp0NE\n" +
                "636TDzobcqRk6qWT53vBgvWvS3RF4UfanUB+l6KwsD0YXOX82TmHIzX2CQApD9m7\n" +
                "rTPvB4L5hbqo2lwlHzRZM3Ejh0X5vazBKU4nADS/ePY7KQjGM/UUD37Sm7ApxQa3\n" +
                "EaMx+QQvmWHC/J53wY1fOAAWj60baZ6+24/GZJzThXPdcFIB5Jh6+iFoPUr/iF8R\n" +
                "N54C7pZJ3G1wV37zp1Dv/32FPqkCAwEAAaNjMGEwXwYDVR0RBFgwVoEFZW1haWyB\n" +
                "DWVtYWlsIDxlbWFpbD6BE2VtYWlsIDxlbWFpbEBlbWFpbD6BH2VtYWlsIDxlbWFp\n" +
                "bEB4bi0tZW1sLXZsYTRjLmNvbT6BCG15ZW1haWw6MA0GCSqGSIb3DQEBBQUAA4IB\n" +
                "AQCeV4X93YQMWRZpSUdxDSFUpu3GOXvJeDB+rUWnTEoRohjWU3QO8qOVqS+WqkP1\n" +
                "EkYSTJc4bs50NCIK8QS1LJPt3jMfYDiVW0WP4sV57XzoLE6qtuaTKn0oAqz5Vn9c\n" +
                "5LG5MTPcYlDEuGQet4DvqtF+oAqjOeAm/rELW22K/JxAR6nZT3wnH5WyaK7nQItR\n" +
                "LFarWRraA8q8sIOVs1HR+vubEYk/5u6n3AXmzxZztWLp5Ow0/8x6XU/IwJlqg+rj\n" +
                "fDJeYJCW8p8G/lStcKSPsBvJC45fZFFI2oOUNs0J+FsKoCihzN3ShbirxMbMY+Hy\n" +
                "ZLL0a0t1JexOoqEvUORZXAFL\n" +
                "-----END CERTIFICATE-----"

        cert = X509Certificate.decodeFromPem(sanRFC822NamesPem).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.RFC822 }

        val sanURINamesPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDCzCCAfOgAwIBAgITBmkNrLuW5WVCtzoww7S9wuDJgzANBgkqhkiG9w0BAQUF\n" +
                "ADAPMQ0wCwYDVQQKDARQeUNBMB4XDTE1MDQyMDEzNDU0NFoXDTE2MDQxOTEzNDU0\n" +
                "NFowDzENMAsGA1UECgwEUHlDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBALKXpkqcSgZeT5NpvKzMdbVy2zJZUaCqF6ghWHAEhebCl9FgS7CY/RcBjZj2\n" +
                "lPS6Xep614zDQbV17q2WliZNJH7s3Q3tq7mhlYDsScd5cZPyM/p+0dCzVTeUp0NE\n" +
                "636TDzobcqRk6qWT53vBgvWvS3RF4UfanUB+l6KwsD0YXOX82TmHIzX2CQApD9m7\n" +
                "rTPvB4L5hbqo2lwlHzRZM3Ejh0X5vazBKU4nADS/ePY7KQjGM/UUD37Sm7ApxQa3\n" +
                "EaMx+QQvmWHC/J53wY1fOAAWj60baZ6+24/GZJzThXPdcFIB5Jh6+iFoPUr/iF8R\n" +
                "N54C7pZJ3G1wV37zp1Dv/32FPqkCAwEAAaNgMF4wXAYDVR0RBFUwU4YzZ29waGVy\n" +
                "Oi8veG4tLTgwYXRvMmMuY3J5cHRvZ3JhcGh5OjcwL3BhdGg/cT1zI2hlbGxvhhxo\n" +
                "dHRwOi8vc29tZXJlZ3VsYXJkb21haW4uY29tMA0GCSqGSIb3DQEBBQUAA4IBAQAx\n" +
                "iR2laJvCh4B6BQ8H7Fytcr8sXf3ih4aA6LQIYy/a2eNpIc58DJimg13rXo8YQ35Z\n" +
                "9Xh6nfhyg3CIrq63UMbIi7NAKzKJMhcMTvcfgXp2TIQWvpFAfothvHL+0cjiOF17\n" +
                "hG+BwcV/MawDZbtJmFjA97XzPJkkgku0dggd91xIi4PEcNLvjCqb81QMExokfa9U\n" +
                "/LkSanGCZHMR0OkfsIFjsNCwj01wYUI0nVoMuLCELer+1rPP03lS2ibiQujZ6C1c\n" +
                "2PC3wZ9Ymy3ysfDzB9+9tgIhqDE6RZ+QWa/2m1Qf10LtAG1EEPA8aWgWU0zcYPEX\n" +
                "vpZ0upM8Tx81CkAGf/3m\n" +
                "-----END CERTIFICATE-----"

        cert = X509Certificate.decodeFromPem(sanURINamesPem).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.URI }

        val sanIPAddrPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIC0DCCAbigAwIBAgITBmn5auEoAtAQyW6jp1JwJ/wwMzANBgkqhkiG9w0BAQUF\n" +
                "ADAPMQ0wCwYDVQQKDARQeUNBMB4XDTE1MDQyOTIwMzUzNVoXDTE2MDQyODIwMzUz\n" +
                "NVowDzENMAsGA1UECgwEUHlDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBALKXpkqcSgZeT5NpvKzMdbVy2zJZUaCqF6ghWHAEhebCl9FgS7CY/RcBjZj2\n" +
                "lPS6Xep614zDQbV17q2WliZNJH7s3Q3tq7mhlYDsScd5cZPyM/p+0dCzVTeUp0NE\n" +
                "636TDzobcqRk6qWT53vBgvWvS3RF4UfanUB+l6KwsD0YXOX82TmHIzX2CQApD9m7\n" +
                "rTPvB4L5hbqo2lwlHzRZM3Ejh0X5vazBKU4nADS/ePY7KQjGM/UUD37Sm7ApxQa3\n" +
                "EaMx+QQvmWHC/J53wY1fOAAWj60baZ6+24/GZJzThXPdcFIB5Jh6+iFoPUr/iF8R\n" +
                "N54C7pZJ3G1wV37zp1Dv/32FPqkCAwEAAaMlMCMwIQYDVR0RBBowGIcEfwAAAYcQ\n" +
                "AP8AAAAAAAAAAAAAAAAAADANBgkqhkiG9w0BAQUFAAOCAQEALCZj3siBnhVWGLg+\n" +
                "hLq20wND+/fQCQA8HWc21zNZ9QwUJl3I0NsGJqgRVNV23X7fDrtcBr6tbGwDr/Vf\n" +
                "InR1MSvgz5L9jPndvrS9eS4glISRYPkfjj76rLuB/BC8G6S64iHV/QK5gCCUEIho\n" +
                "h074j+UN0U4jXpe9UDmBM+CCnE+bqVA0TxNExj0F0W3s9Z8ssJYMFt8fkEVhFT4O\n" +
                "XhOBgvtMw4m6UTXkBZr+CaephrKpfaPvuLpSlJ3NvE/fvWsUWNp26CpHKQLmEtAC\n" +
                "bUZpcXKznl/KIPKx6TRvnNx5DQQzrM0ExepPPALNSDcj/1wZ35KQ/mmNg1zZAUMP\n" +
                "fHN31Q==\n" +
                "-----END CERTIFICATE-----"

        cert = X509Certificate.decodeFromPem(sanIPAddrPem).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.size shouldBe 2
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.IP }

        val sanDirNamePem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIC6TCCAdGgAwIBAgITBmn5cZxxyn9QTQCzrgSRPum/ETANBgkqhkiG9w0BAQUF\n" +
                "ADAPMQ0wCwYDVQQKDARQeUNBMB4XDTE1MDQyOTIwMzcwNVoXDTE2MDQyODIwMzcw\n" +
                "NVowDzENMAsGA1UECgwEUHlDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBALKXpkqcSgZeT5NpvKzMdbVy2zJZUaCqF6ghWHAEhebCl9FgS7CY/RcBjZj2\n" +
                "lPS6Xep614zDQbV17q2WliZNJH7s3Q3tq7mhlYDsScd5cZPyM/p+0dCzVTeUp0NE\n" +
                "636TDzobcqRk6qWT53vBgvWvS3RF4UfanUB+l6KwsD0YXOX82TmHIzX2CQApD9m7\n" +
                "rTPvB4L5hbqo2lwlHzRZM3Ejh0X5vazBKU4nADS/ePY7KQjGM/UUD37Sm7ApxQa3\n" +
                "EaMx+QQvmWHC/J53wY1fOAAWj60baZ6+24/GZJzThXPdcFIB5Jh6+iFoPUr/iF8R\n" +
                "N54C7pZJ3G1wV37zp1Dv/32FPqkCAwEAAaM+MDwwOgYDVR0RBDMwMaQvMC0xDTAL\n" +
                "BgNVBAMMBHRlc3QxDDAKBgNVBAoMA09yZzEOMAwGA1UECAwFVGV4YXMwDQYJKoZI\n" +
                "hvcNAQEFBQADggEBALD7gsmUYvQwDbR3R8vIkcd8eH0J1DXXYBAFaUC1esFwhOqm\n" +
                "igXt3Y0g6hu0XbWovOd79Qh2gFh0j2nvMjY4sKJAursyjJPfPuyriipPYipJOEJf\n" +
                "FapBVlo2fKNRwuH3Hs3ap1EY2u95z7WpTj2/hTiZV1fKvdWzaLP2r8sKQCGzq4NH\n" +
                "I7e1xqcil977i3HBsLpSEbEh1ljQNVavzTKDlSERuXMtSzKf9W8xk9yq9r2onW36\n" +
                "QQtrTydgCfs6SpeDnBVb9TZ//VRQbCYUOI/bVUp3sJn7ko7akceZlpLkAYnhhVEV\n" +
                "LmOZzeKe+aDRDPoQSObFlOiHAxz/myd0QtWDYi8=\n" +
                "-----END CERTIFICATE-----"

        cert = X509Certificate.decodeFromPem(sanDirNamePem).getOrThrow()
        generalNames = cert.tbsCertificate.subjectAlternativeNames?.generalNames
        generalNames?.forEach { it.name.type shouldBe GeneralNameOption.NameType.DIRECTORY }
    }
})
