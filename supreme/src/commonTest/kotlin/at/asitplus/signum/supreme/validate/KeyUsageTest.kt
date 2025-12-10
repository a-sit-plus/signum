package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.validate.KeyUsageValidator
import de.infix.testBalloon.framework.core.testSuite
import at.asitplus.testballoon.invoke
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

/**
 * PKITS 4.7 Key Usage
 */
@OptIn(ExperimentalPkiApi::class)
val KeyUsageTest by testSuite {

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
    val trustAnchor = TrustAnchor.Certificate(trustAnchorRootCert)
    val defaultContext = CertificateValidationContext(trustAnchors = setOf(trustAnchor))

    "Invalid keyUsage Critical keyCertSign False Test1" {
        val keyUsageCriticalKeyCertSignFalseCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgIBHTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowXzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExLzAtBgNVBAMT\n" +
                "JmtleVVzYWdlIENyaXRpY2FsIGtleUNlcnRTaWduIEZhbHNlIENBMIIBIjANBgkq\n" +
                "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAshkDAkc1NgsehY25cyVzSEjWwYU6t95G\n" +
                "/bdkWf9DwvSkBxz42UAB0DfeBaHlbsgyVPjecL2N2bBpu4Jn9T03xEaMfcZXsyI+\n" +
                "Be6psiAHVoVI9yTqESpjDgwWC6qE+g6PcQq1pYxsGzWlcBm+nxxpb0biMg0pTgcD\n" +
                "KUtkK3UeoUJ15K3nDEekwLkLFwuBBFGzfOFCp9PImJh432RT/zzy47GGF9GNNDPa\n" +
                "7iAZDmKadTAQ2RFy91qvUWsMxTdQ5wR7mzYRQwjzJG/3QBUKaSl5jEX+U7wzI20b\n" +
                "OAHMdiEfsDNKXlvbIWloxcmVHLrVnzyFXgoB4ZYUydsAZoqW4RUaIQIDAQABo3ww\n" +
                "ejAfBgNVHSMEGDAWgBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQUNFUL\n" +
                "Z/wcsdzCcgoU8GPp1JvwY/kwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1Ud\n" +
                "EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgECMA0GCSqGSIb3DQEBCwUAA4IBAQBe\n" +
                "d4ZoblyGZ2/KmDlPWpOb1UDgc8l4fTwKDuDOch2en3qqX22Lbfpc3XWB+cOvcneu\n" +
                "TvU3GCC2udrSk867vxd6LsiUPdfieO58b0au8+myabu+ICeOeWtug/++HvHiZYPg\n" +
                "dJI39eSmMC5iaiSUkcdyNdH6IwkB3WTlfFwQo62T+zC044ajD/1nH1F8yNx6bJPb\n" +
                "nCcphNbufW7lN/3B7bpiz4EKajIkvBk5ZP8b6amkDO4fGQvEgbZGhNo2TwDPJh+i\n" +
                "97WnDFkCgOETr6GTgfXj+BfABCKduqpl4H/cUG0zt4QI4SMsuUvqTVoHTUc+XNMW\n" +
                "kaLapuUYQMDC/P0XLwPk\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDvjCCAqagAwIBAgIBATANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEvMC0GA1UEAxMma2V5VXNh\n" +
                "Z2UgQ3JpdGljYWwga2V5Q2VydFNpZ24gRmFsc2UgQ0EwHhcNMTAwMTAxMDgzMDAw\n" +
                "WhcNMzAxMjMxMDgzMDAwWjB5MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBD\n" +
                "ZXJ0aWZpY2F0ZXMgMjAxMTFJMEcGA1UEAxNASW52YWxpZCBrZXlVc2FnZSBDcml0\n" +
                "aWNhbCBrZXlDZXJ0U2lnbiBGYWxzZSBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANf896E4DA1yEvLrX3/cGYNrRlVf\n" +
                "A76pwTLL8ttdnT5H5CjhJ+iiSRGJex/SIqyw65lOAji765fxX7F4zxrYr3fdS+d2\n" +
                "dPzMwT4K7a7EHoM+CbjS4cK6/8h6YinfliLa8vsma1/cNNTImaTCAwbJu12j7PzY\n" +
                "9c/z6mkdrrtl2FFO2QNATVfkr+W0ySGvl6i3ptILE4cveSRZcUBXJZRF5PF35ntz\n" +
                "DETThlUZ3gm3BpW+qVskj4EkaVvdsVh4dAU1knFbzC5QeamvtIsaVnOcGl4bq7dy\n" +
                "PQcNI1BNUfcM8ohqq8DaHl+lxpIkL2Wctd+C/TivzyP7dAXFk6tkjWcJ/SkCAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAUNFULZ/wcsdzCcgoU8GPp1JvwY/kwHQYDVR0OBBYE\n" +
                "FIQbJBPifwi611fyrtWctSgqZB4dMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAJmjrWO0GlQGCOakvQrm\n" +
                "qhUsHPSqpZKgM1i2NSp+MnJp3zJoHa9kp8jwkykLSK2AuKKfoLOixQ4r6dLmwLkJ\n" +
                "rlB5V5vmNVUCSqgIjD+vN2QAiNsE9R0ct40c0XUiTNv+87XTzZ0Y9XrsvHi5OAhy\n" +
                "t0d3R6lFVDmLB0S0/BueNpW9JPW0R6Hj5p9aDJyYHllAWNzONsr6PVwIfKAw3I2T\n" +
                "PTS2uEwVSCRi1bp1itJJOsefwogh+EXVwAaT4CcA98XllAGn4aw7l3niL3GRhDN0\n" +
                "r4a80Zy4bCS42pAvqpq7BvzGlP3UaW5vRSPwV3MGyX2W7765rm05lT/QuGApTZ+K\n" +
                "Igk=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(keyUsageCriticalKeyCertSignFalseCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is KeyUsageValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Digital signature key usage extension not present at cert index 1."
    }

    "Invalid keyUsage Not Critical keyCertSign False Test2" {
        val keyUsageNotCriticalKeyCertSignFalseCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnDCCAoSgAwIBAgIBHjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowYzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExMzAxBgNVBAMT\n" +
                "KmtleVVzYWdlIE5vdCBDcml0aWNhbCBrZXlDZXJ0U2lnbiBGYWxzZSBDQTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALuW25Rdl1a11hIRQCfJWGwgZNpJ\n" +
                "8Bxjnvmd+5HmQB2uTgWTPpIs9xfWCuOqqCD/jVSS97nyBQQtp6I3dQvU7Ssmkz80\n" +
                "7y25FvrdcklcYjFKeKra/Di2suavIb3nlf5H1hRIzIejKqFxIDjT4QOi+kNdArr/\n" +
                "cJM1nrZEhnNErXJ8qDpcb8k4fzbmodDbV/g1zvqY/vmh4iYv5qiw3PFRR94e613H\n" +
                "gatzeOgFdu7EpTGAbNp0cGnsjvSuFb/XjY9EAtQoQiRmiiXbBnmoDIqOM7lktYJ4\n" +
                "6Aly5kGXqXS3ZkkWERHRepN4B9rA8C2bppjGxQ13TKHFqeQfOgkvpGi7rVECAwEA\n" +
                "AaN5MHcwHwYDVR0jBBgwFoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYE\n" +
                "FLIl0igw0FVobky1wkjzypsV8kBFMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAP\n" +
                "BgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBAjANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
                "LFhwyCZWomHkwIVAZ8k+3AqH8bVC/JcN/8St1fY/0BCt6pLeFOWLLXpflPlvvNA5\n" +
                "SZbJLDfE3VOOYrYqwJEnmy979I1527wPGcj5O+jcDg2AWBpMt1qPPafftSGQxx7t\n" +
                "UEWw8ZQvsEAab3Cof4p1/DXCJKOpx4zsXrz/OFBkSx+Gq6v7n+Pb+4g+IojVaxnx\n" +
                "UO8xUAaQzjxv4yVfQQw3fzfrY6a99UBUOwuIPcQ+AKv80uU3aqgtvkoOWqs7R96h\n" +
                "rnEWe9qZj2hCg9Fpwz1hyg2cXpkBfL5Kki5zUTaNhad+6iv6p+tXxx7W8qs7Fti7\n" +
                "ziEwUI8u1HYLbCGCGFsuhw==\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDvzCCAqegAwIBAgIBATANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEzMDEGA1UEAxMqa2V5VXNh\n" +
                "Z2UgTm90IENyaXRpY2FsIGtleUNlcnRTaWduIEZhbHNlIENBMB4XDTEwMDEwMTA4\n" +
                "MzAwMFoXDTMwMTIzMTA4MzAwMFowdjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRl\n" +
                "c3QgQ2VydGlmaWNhdGVzIDIwMTExRjBEBgNVBAMTPUludmFsaWQga2V5VXNhZ2Ug\n" +
                "Tm90IENyaXRpY2FsIGtleUNlcnRTaWduIEZhbHNlIEVFIENlcnQgVGVzdDIwggEi\n" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc8DNtbU9YabxHAoWqRyRxHTrx\n" +
                "VL8YwSE94cbcBbMA4tskut30Eqd/j1CYbCrD9KIyn68THeypVDFGL82wg3/N2lZM\n" +
                "P44b8KvH2ouJNqljDVDhipAu8Tjiun0y+3L9diMlpsfrx2ZSdDO+WbeHoUjovd8Y\n" +
                "DrPtG0U6THisgQj9sgWI8oIgPpQRjoMIb1ZAC/IsMPYVNJL/a14dlqit2PsGpLnW\n" +
                "RYEG064MAde5SHUfgV66pwAxisEWH5xl/v4Bbrh2mqMsQ16izLKStQiuW/sVMEdH\n" +
                "iEJefQh4y8anEbWkudAUDvV31mUyHivZmfz8eldAy9ICi2RdSEOf0QCfARalAgMB\n" +
                "AAGjazBpMB8GA1UdIwQYMBaAFLIl0igw0FVobky1wkjzypsV8kBFMB0GA1UdDgQW\n" +
                "BBTzsk4G1clcuVdkoLbl/++tircPZDAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAw\n" +
                "DjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQB4eFm1jkEg53bNCSXO\n" +
                "pa2ViAfw7FgAGt0+trq/MaMv0SVuIWZRgkhDWSuTffNi6zC0cIXO+H/IlOA9pPz9\n" +
                "CHnH9FRigpZleyl8/WMx9EeEYzpS8Bde6LLZh8nzeLiBsXZ3A9+Bp8lqfgMoj3kW\n" +
                "GUIcMGyN0MS4PtXuuwz0Ur3FXfyXEEJCqwQ3iyiIfDvYaA2Qq+ttHZcJlwkzeMEZ\n" +
                "pwM/lZZEnapou8sdKtfbA9h0+0ep6tamOC6tRv7Gz4OGtPKWstl0jdf382Oq60hX\n" +
                "0TqCs8uCX5l46vnYweDOFzj9118sceZ9XXCYxNmRXPNbEf2guCrirvPZCRXcmE0v\n" +
                "7AOi\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(keyUsageNotCriticalKeyCertSignFalseCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is KeyUsageValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Digital signature key usage extension not present at cert index 1."
    }

    "Valid keyUsage Not Critical Test3" {
        val keyUsageNotCriticalCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDijCCAnKgAwIBAgIBHzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUTELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExITAfBgNVBAMT\n" +
                "GGtleVVzYWdlIE5vdCBDcml0aWNhbCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                "ADCCAQoCggEBAK/akbKDSU+jyQyKaVyIOSz1eF/8IBeTVffB6t4DDAzrnRLvfKPO\n" +
                "QaKZb2v5iqF1M2bBoKaIdSfcI5At/JXFHJD7H4EGHkT9sWMV3Qyhw9peIr7We90R\n" +
                "S30KHCOsXU4UYx0Cqgg9A1coxkMo+lopBwaQMXdxSRSLshfGuNKrjCcttOxF/GXm\n" +
                "hpz8kMPBLUKj9OFFudTylI2DD46FxcwgJ0JnBPOll+fpLPYVhBAM9Y5uHjcanl6x\n" +
                "5U3Vu2ENZ+v8wAXqFFkl/ySMO8oXidy+2ifYjxPJsvAC/A7BID2NG7y6F90+tHOS\n" +
                "7I4pUA2dwp3ju6p5yj3o4zSX/cQDvuHj99ECAwEAAaN5MHcwHwYDVR0jBBgwFoAU\n" +
                "5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFMGQEUrZtCvFcH7OjDtiWOW7\n" +
                "lytzMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MAsG\n" +
                "A1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAHJthW7o9tlSkPicbKxW3xOHN\n" +
                "vcod5xj4RNcMFpz3AZe1KDPm8vSO0P20uzUo94BcwKGOhf1Ecp+8r9Y7O/dpyIz0\n" +
                "FZRa5JKW4NA0LlAuhsD5f4gLpRbY4Nr0SS0w3k8ycSU3uxpPCiD92tvih3GAPne+\n" +
                "d79uPxmFSOVwgiPa6uLz0nnlAwgbMl9NiLpdzsLnbIi1saapuoEwMNWF4VXd4DDO\n" +
                "MfOh1tHOwbyfmJuQF7rl7dGkhQN0e6AHJUsNigI3i4wHf1GvfnpXrzUoz8QzmUWf\n" +
                "QQCza3OcdC2UUN905ztpH/+1bgtUJE/alfclVJZEHaWIhIPg+5//Op74d3oK4Q==\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDoDCCAoigAwIBAgIBATANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYa2V5VXNh\n" +
                "Z2UgTm90IENyaXRpY2FsIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowaTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExOTA3BgNVBAMTMFZhbGlkIGtleVVzYWdlIE5vdCBDcml0aWNhbCBFRSBDZXJ0\n" +
                "aWZpY2F0ZSBUZXN0MzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALez\n" +
                "B7zAQcz+cwTNzcRbXADc2II98d2UkCim1OerlAh4XSPePFqkPmCcuijOF1vTFsxc\n" +
                "eUBcnBHO3iH6Dw6LBoJF8f4slPhGVzTtmXjD/0N1/x70ypCbNHeCv1Lxfn/M6Ufi\n" +
                "bYEYqZnL4D9i6pRWU6UcjRRWfoX8zEyTdShPLhxIUovvEwStmd3ISQvgJKLEbAJc\n" +
                "+EEPA1k/bcXJEf3VVhmx0kjNTqWXJP+X+JfG4i1AmyhwRDbXdwND2lzPOizThff+\n" +
                "4gBaxJB0cdW7wHwqrnSTQmFOB4vSkgQYFHxgBplJ2Eh1t/AyokjI9imz06VmfhFk\n" +
                "kyuRvGqaxBD1W6zY+bsCAwEAAaNrMGkwHwYDVR0jBBgwFoAUwZARStm0K8Vwfs6M\n" +
                "O2JY5buXK3MwHQYDVR0OBBYEFJ46eWPPLst3JdrmpRlWguBUS9GrMA4GA1UdDwEB\n" +
                "/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBADfZpIsEnc5hM5JwyXKi3HdQMCwHRQvGadMNqh/3A6SSIWJwU5+8WeorwD1Z\n" +
                "SikyE+AXC/cOfSEksVjrCWY3ezWVF99+jaQFqgE8lcws1LlytaN6sRY7AdEoQUhQ\n" +
                "r+YawAvNZgbkRRB8LvhWUWK/66N8rkVFJVahJCcfEGzQdNBryag9SQrcqYigfV+D\n" +
                "Ysob5iuSOJAoGlnAtHVtOwogjfZ1ZQy//P4yJ+IbzE3u0kHMTTqUrIeB1RWqy1YQ\n" +
                "QTpnFVcmuI0utFmhEDYz7w5ktTQor7cwojxc+NpA8qzvRn6hiIeqemqrYIFAzhc6\n" +
                "EI38iiO0ZAhjvDBgsERMLmKUTR0=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(keyUsageNotCriticalCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is KeyUsageValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid keyUsage Critical cRLSign False Test4" {
        val keyUsageCriticalCRLSignFalseCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlzCCAn+gAwIBAgIBIDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowWzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExKzApBgNVBAMT\n" +
                "ImtleVVzYWdlIENyaXRpY2FsIGNSTFNpZ24gRmFsc2UgQ0EwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQDVXFpJZrrfE3RhnognaEW5+Af+QIHZD5UHsNHJ\n" +
                "5+52dskADZ27OVATF0lxfJFCsvqg+xF0CwUnPGAAvicTqbn5s6VfivsitBKgJtYv\n" +
                "7mQHmnA/atFcsstwIM4a0ElZktPr3uBoVxfxJPve11Pkzn54JOO7iWMMqvbCnUM2\n" +
                "rL+CDR+0mVStkYCxLbUDYIBHvjBua2K2h6zffk+UDf1cBiOJjBKLdQN3gJDKvgBz\n" +
                "P4icVr3SOKy7CeZssY9qDvfs1VIXbFdHDNqAQJqIDrmdYFaWQ9Frg9SYdJ4nCNyN\n" +
                "7eQs78izC8jF9EjR7NAIHD9l+PeznskhJ8hfHOQ/gIiccfPrAgMBAAGjfDB6MB8G\n" +
                "A1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBTCymn1tK8T\n" +
                "LfSc8hFVyyows9JaSTAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYDVR0TAQH/\n" +
                "BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwDQYJKoZIhvcNAQELBQADggEBADmfRFtG\n" +
                "DU7X1eSxvzMRLpmjMY7rtbEUvSMJXB4kTt9/QsKPucJhG90897xCca8i8R2nBjl6\n" +
                "Wt9YorVQIXg1usooaLj0d1/MWgRl51Tf6rWRlpbaG3sYuU9lfu/b1TPHLdh+iihD\n" +
                "OrJRrv2VhNyurI61IbwgOUfnc/185PdIhWMyFMiIg+S7k+U6MM0b0m8tfAwQMS7W\n" +
                "qVKV/DZdutJFDNPqWUNW9KsVPQreAs0BHfeH1U3Sj5y3678pOOW/oWeQECv3hptF\n" +
                "xIeE8gCSz8ckM75AJnqa3bI4Qfc8Z7h2KYbqg4uh5Lvy5sjT6EmzOFhZfxPkkYuZ\n" +
                "v7kVKEHrXEIv20Q=\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDtjCCAp6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTErMCkGA1UEAxMia2V5VXNh\n" +
                "Z2UgQ3JpdGljYWwgY1JMU2lnbiBGYWxzZSBDQTAeFw0xMDAxMDEwODMwMDBaFw0z\n" +
                "MDEyMzEwODMwMDBaMHUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRp\n" +
                "ZmljYXRlcyAyMDExMUUwQwYDVQQDEzxJbnZhbGlkIGtleVVzYWdlIENyaXRpY2Fs\n" +
                "IGNSTFNpZ24gRmFsc2UgRUUgQ2VydGlmaWNhdGUgVGVzdDQwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQDEU52VUxkPNxFuLOEIPwROevCUVbZbolJu2uOK\n" +
                "hMqmu3yXDYKR1FBC5xGsxfZeep3tn+PGr9z5+O2gaD39SGxlMhxvSdbVc/QT1u25\n" +
                "0fTq1U0gte59c0JsrG9MhvZBwz0kC7jMkc/1De1UTKtz8kSLwTqZgKQKruSHBgM1\n" +
                "QLeMl47cR27fiUnzXAa2ZEOGIByyxdEG37yXJ924NHffS3Ig9PrPYFyt74Ck9Fir\n" +
                "pc+gS5ayFmJLrmerYNTDkA1lVehXWkxZeK/xwj1+PIhlOFylbKKPrB3gFN6fqppT\n" +
                "TkP/PSLoJcAA40b91W8T1sJvqRvgx31t/72sTup5zEUIHnglAgMBAAGjazBpMB8G\n" +
                "A1UdIwQYMBaAFMLKafW0rxMt9JzyEVXLKjCz0lpJMB0GA1UdDgQWBBQ+1JjhVKTI\n" +
                "Ycfsx9NS9lCKWrDbIjAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgB\n" +
                "ZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQBiFYY8R0mw8pMTdH+nZzSKMKj3aONg\n" +
                "mhYYsS5cKGpx8oQOv/iNdYZf+W2f20nLKt9iKoCwbV7qWFai5HasT2AeXypTgEMc\n" +
                "nRcn5NkQCIkOFYjKwouSFUF9Lt5gcRfQhD2E6yEORH+6OuhRhkydk0NbmOu3EctI\n" +
                "hR9RKSIY3cCS1got9Kxmj1N8/KFqKTOXleg6tdC27Fqo3tfPQOYccxagBPAzmZbR\n" +
                "f17XUbqiY0fl0CVUBZImmUY1C18ov0xgnUF5m7vc+DQOhFemNemdi3wMbIN77Dva\n" +
                "925L/R1Pek6PDaTRYrikU9zS+CkdEgfB7Pt/+PkV01xA11ew60ob+QEB\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(keyUsageCriticalCRLSignFalseCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is KeyUsageValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "CRL signature key usage extension not present at cert index 1."
    }

    "Invalid keyUsage Not Critical cRLSign False Test5" {
        val keyUsageNotCriticalCRLSignFalseCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmDCCAoCgAwIBAgIBITANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowXzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExLzAtBgNVBAMT\n" +
                "JmtleVVzYWdlIE5vdCBDcml0aWNhbCBjUkxTaWduIEZhbHNlIENBMIIBIjANBgkq\n" +
                "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4ajkrGWOSxFEG9vuWGeWpRVcosWQyfZP\n" +
                "JV13VfTNb+3Q6Ke5L218dww1FtrmP99ZBbbX8VTaLT9Hl36zdCNhXfNDjpj92N4F\n" +
                "rM93HPFrMLewZnfq1d3zWvtPN6UYNKyRozFsys72YmIswHZb83uAltVNKZNaoIhx\n" +
                "9oDLf6BudU9MYynVUnOskvWbJbbi2SqjNW7dHP7boiDi5Uy+IdyiKvkyTHnaH3OC\n" +
                "gjmQ3lWXpg+2unulTZabYaR4twj1hFh2XgZF946GAg2sy8ux4g9lKR7+HL1BNC5Z\n" +
                "PBzKHqMPZu8+RCUA+gHUeh5xwRFBg7wq1Gs5FXY0BB86bDdjJrDrLQIDAQABo3kw\n" +
                "dzAfBgNVHSMEGDAWgBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQU+X5S\n" +
                "oHlmBAhECGV5EA7dkOZD8dgwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1Ud\n" +
                "EwEB/wQFMAMBAf8wCwYDVR0PBAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQBXNr7R\n" +
                "CtJ7NH6ne9HBNzkCWsG3bwfaR3tD9hQNR5w5fyX0LKwBhnX8oH6dAHe+YHZ5oRlF\n" +
                "yOeAZ5tjD3XR1WGFJCEHWQ3VmHOVtHLoc5YNgUZcn9xO7KLWiLsRPm6Nyd7AETZd\n" +
                "/2EQUcHecRR6tnTKZJLeZzddzGnb9ThWvdYO8VaY7ipNp/fL+odZx98P8yiwni9f\n" +
                "gspeW+GDi8xD6U16qXGYLJ76y1gkSYs4IZCx1Pqn/MJTsx42cHfrRLaomVzOGraa\n" +
                "tjeiql/jUOb6IWX84tabge5xp3nMD1xfCFaGTaLMPiWtEhgFqZEzONP8R7d+15gr\n" +
                "tWm1TYtrpHu3POhY\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDvjCCAqagAwIBAgIBATANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEvMC0GA1UEAxMma2V5VXNh\n" +
                "Z2UgTm90IENyaXRpY2FsIGNSTFNpZ24gRmFsc2UgQ0EwHhcNMTAwMTAxMDgzMDAw\n" +
                "WhcNMzAxMjMxMDgzMDAwWjB5MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBD\n" +
                "ZXJ0aWZpY2F0ZXMgMjAxMTFJMEcGA1UEAxNASW52YWxpZCBrZXlVc2FnZSBOb3Qg\n" +
                "Q3JpdGljYWwgY1JMU2lnbiBGYWxzZSBFRSBDZXJ0aWZpY2F0ZSBUZXN0NTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL6kAGMAGNnO8CvJ2PjAYd6v3pcL\n" +
                "vPjKj7gXi4mOj0xJc1rp6f/8pxy/Ua1aPCyRiGonwfc8rZb/mdR+HKpTTJjZgygW\n" +
                "26aX93qRrJIvvb/Vie0yu63PraLINIUKzg4FeTIAmCu3g58FhVdsaLALdA9wD6st\n" +
                "Ru+BcE5BbZCssejYjMxiAxjrv7GWE08R/O+6u5GxqE+3ZWg4StDq1UyvDL/HhEjc\n" +
                "DmuODxI/sruN7fMv3SN4o+GfkkennaAnYE4YWK37p8gbeUSglVsTHliyEPFcclH0\n" +
                "sAElmBLEOfkZK6XRGQVln7g4+CjmbSuvuoZUKT4RHOPTwdoXB68uwIALDW8CAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAU+X5SoHlmBAhECGV5EA7dkOZD8dgwHQYDVR0OBBYE\n" +
                "FP/OMrJ781bfdvIdIFOwNrNmArfaMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAIvo2bd8LXplAdh4RhqY\n" +
                "XGsOB5E6oyj5lqaZ9SH+wi8ss5J+Oiv28rYRYVqYnS4ceffJz0q9waAuab8GIbfS\n" +
                "NWXIfsXTncRqEq2kM3W+/77qIItkjcfEOCxV3rtWayCd/ugW+dwO+YChBRdiAMV6\n" +
                "VkBLR4lo8pO+rT/pS4REBTZbdoZ2ToQB3RF2M4AJMrHGzeBi4vMNcxTVo9iMnvOb\n" +
                "QvGLwU20mmMt5+WsR8HZviXmOnyhikb/pba5sLhFm+kY6VZoZ4eMaGIjbs9okOjs\n" +
                "hOyxLkfZYsICWxDMrHeLnat1/hV7dQ2jZd4iZzvXaHfRK16y9c9kX6nXeQRDuays\n" +
                "HpM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(keyUsageNotCriticalCRLSignFalseCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is KeyUsageValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "CRL signature key usage extension not present at cert index 1."
    }
}