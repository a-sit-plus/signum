package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.OCSPCertRevokedException
import at.asitplus.signum.OCSPCertUnknownException
import at.asitplus.signum.OCSPExpiredException
import at.asitplus.signum.OCSPMissingAiaExtensionException
import at.asitplus.signum.OCSPNoMatchingResponseException
import at.asitplus.signum.OCSPNotYetValidException
import at.asitplus.signum.OCSPResponderMismatchException
import at.asitplus.signum.OCSPResponseSignatureException
import at.asitplus.signum.OCSPStatusException
import at.asitplus.signum.OCSPUnauthorizedResponderException
import at.asitplus.signum.OCSPUnsupportedCriticalExtensionException
import at.asitplus.signum.OCSPUnsupportedVersionException
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.pki.SingleResponse
import at.asitplus.signum.indispensable.pki.X509Certificate
import de.infix.testBalloon.framework.core.testSuite
import at.asitplus.testballoon.invoke
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlin.time.Clock
import kotlin.time.Instant


@OptIn(ExperimentalPkiApi::class)
/**
 * Certification-Path-Validation Test Tool (CPT)
 * https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Freie-Software/Certification-Path-Validation-Test-Tool/certification-path-validation-test-tool_node.html
 */
val OcspRequestTest by testSuite {

    runBlocking {
        SystemOcspCache.initialize("./src/jvmTest/resources/ocsp")
    }
    val ocspRevocationValidator = OCSPRevocationValidator(
        DirectoryOcspProvider(SystemOcspCache.responses),
    )
    val context = CertificateValidationContext(
        supportRevocationChecking = true,
        date = LocalDate(2026, 4, 10)
            .atStartOfDayIn(TimeZone.UTC)
    )

    "CERT_PATH_OCSP_01" {

        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR1MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE0WhcNMjkwNDA5MDgx\n" +
                "OTE0WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC21+h3HQgl+kCYX/fKgVbHmXXs/EWW\n" +
                "yGA1JRBreuU/yWApH7a9X2NCvcN9iqpqUqeEdA4TiA//nxH60lnMgDBs/b9Yakla\n" +
                "RBQ8kGXk6sA4j2aS/Un67K1NogRQl+GMXlVO6sAw4Q/NXxH+/gQ2k0QU7iJxcGI1\n" +
                "XmnEuReUOBJ32/a5ByzJM0DYwf5DNWwadButVx1xkujG+XGN4yBCPQ+QYGPYqHM5\n" +
                "7wgQ1pcNk8XvAxfXpaAnQ7FL4RbHwXnS4zr/p79mAuKV8LoML0dawmxQskLYN7OD\n" +
                "a5VyyfLdYiUtyNOXn9hGL+Jq0zgZ+ojoh9ZZ10hAySmy57LZaY6w7HDZAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDFfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFMuNk1ym\n" +
                "Q/+Kh1yzA/ICrYq5UYHnMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBqorAwfDKg5Pf0cOjvII1mG8QTfMjEhLf5\n" +
                "xBvGoftV8LtNRkpMGg25QkgZP5ADPwftYlNhDab/IeOYyxw3VwRfm17goSn1MmMO\n" +
                "QwoVzczsy7BfS6q/NRIdyhuQUoHfCMMT50IqxbtLHpAk6CkOJ2LVUj1Ug2I4k7zx\n" +
                "QPwwjsDvTLo8RUur4JTKQdnpu683ogA/T+FuKZd4iI1+V9wgRXSUtUvY2AjkoQf9\n" +
                "TKq+dWFIwXqR8nyCkUfmr0nPy2xaiuzP6sJuzJuUGy5PesoWAw5EZy+Ch4It/Zj4\n" +
                "WRomP9UPTbWkklosPZf2vBJeaj7eXwkM5bFcw0oOwuwvJ46vXjM3\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWUwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxNFoXDTI3MDQwOTA4\n" +
                "MTkxNFowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5QDHtGwEmPOcEf3MCcygsQHXXAmVQyDHy\n" +
                "y+HmVZEwCEnc+LxgnVblf4/vA3Wo5uz4e6BoOCG/DdRsdRypytzLGUV+35bDW0V5\n" +
                "NDMaqNmU+HFpmFVy8bYKs5AicxoGosM2PNSXHZbYwEnAn2oGgaanoH8YaQNlk0w4\n" +
                "70ECcNz38z94Ay99mMaOGCz6bslmjlhOkqbh6LFt25bi+y5/qgD2mgL8ACvSfkPp\n" +
                "VWB8MMdkfNX1TQiCxUz9x0dhgRuMFkU/OaCCZj4+pCcry8rxmCE1lw2BkucxLLbX\n" +
                "6mIysau5Imq9ceOSIQ5tuWgdjZXNd+bfis5AIqH6e60s2WNsnxYvAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDFfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBTLjZNcpkP/iodcswPyAq2KuVGB5zAdBgNVHQ4EFgQUoS28dLGQVqYB\n" +
                "vc8VwQse7PgtKb8wDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBk\n" +
                "P0AzGityhPGvjLYSvXmYhTADEUKKMdBTbGzGCgpdhSI0Fnwe921mzLOnARwga4Qj\n" +
                "hz7QU8BsisoYwbLs3QXdxkX12X0B6yOhuF7YD0LbiWD/zu1kXK3Z4hkzTKczW1/j\n" +
                "uenIzyRa6xu1g9PwaG43T/mFhIM6S1eWHqSEzPFR5IyQrwdPyodZMXrkksplbm4C\n" +
                "a0td0yRaL6rUqT4OThz+QhSaQesaAgR3aXA1H+PDSZysxrBz23ZioXjd3xGWPcjD\n" +
                "WIdrsvE71Z3os3ku41DKUE0Xl9A9sfN16hgyie2SKgw2l555929Gq8PMYotUZHpA\n" +
                "hYBAE/Xc/BpubNgX98eB\n" +
                "-----END CERTIFICATE-----"


        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))

        shouldNotThrowAny {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }
    }

    "CERT_PATH_OCSP_02" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR2MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE0WhcNMjkwNDA5MDgx\n" +
                "OTE0WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrqB1lmdjuel9D7zE3XtExu+gfj5gD\n" +
                "B/+QixltNHYjcEfXDZchyZ5sMlaeF1yHznVCcJXmmyaaMhCBoLEpMBERPpz4Fgc6\n" +
                "1ThEwFZgb6jg4X/J7IcsJvhLmXhsDEFyC87/AzWTywSlUzfhEFYR9d4pzLT+JQeA\n" +
                "oMbb1NL4G1MulBHEijzNDekGul2nuZU3QgjSYknB8j6Grp0Zl1aM8sPPI0ad5ne2\n" +
                "Tb238mhVNTYfaSCKeaZE329Sw2WzyB3Ax680+eJwa5WWbFWtfyADDPr0MI+QMoJR\n" +
                "FBz0hu+GdxdWD/HMoT6zqxdHkNjX9d8waVbY2vheFI0Dr+Hc+suaQ7IZAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDJfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFLoHfD2m\n" +
                "uZ4IaCRSBSYYnVH2E8eOMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQB6EaanPlZMECZrSiNxoNKFoLsV5xUJsRlV\n" +
                "Ef5DQOzBwbsCNwVNzWxj0pXZrH/MhlMUY/NQvpHzX1alnKqn0uUOT3lNAFCN7nNW\n" +
                "3gWKzqHtiWRzsoK/wgQ9CQnspZPbRAZnOnoRtWvd7CiIlsj2udR9PgU2xrjCHGb4\n" +
                "aULoT4ImkZkMXmm7vvu0uEElWWQ0+/9D+z8YTGZdThstrKFgZEarKfpARNwwb2vX\n" +
                "aut12bb7H8yr/5CoabxZVohE4kc0s6dE+8yKDsyOZjN9ISS9kJcrAjETXC5C+XmO\n" +
                "fOd5vwM1sFlF6FL9eeAXPEpgL4jUczEFToOVTdoi/tEXUN+PNPjM\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWYwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxNVoXDTI3MDQwOTA4\n" +
                "MTkxNVowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYgVHmJu8zgay5Gg9+lxS3+rVv/gbhBcPU\n" +
                "H9X8kjiIlVldf7D/jDixrfa0g34x9QWqdfaKTVcw1LaUswUYUlkCLC3aOpqX33wR\n" +
                "LWzZm/w3X9St/fgP4DeywxeIgotfHEIIb/gboUIcgyLn1W5zV1HhjBdd/n+fY1D0\n" +
                "TzGIIalfFpiLbM+SSqkoI63HTfQRl6zVYj8KWZ/ITqJbBYszU7Mxf9emqqHnijI+\n" +
                "47f+YzmtbCaX/YF7v1IE8ysrm5lX9HapmZD/43Sj6Xmav3m26IYcAAd91v6d2VR6\n" +
                "oKQzf1Y0SIuUdHFdCcRCCK4k2yPkRLag+oGieREcwquW0CCwcC2DAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDJfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBS6B3w9prmeCGgkUgUmGJ1R9hPHjjAdBgNVHQ4EFgQUoGaOzQ4OyGGA\n" +
                "NHYSp7kDggz73UMwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQCr\n" +
                "bK6WkZQ3d7bYoaMaW+sYdq/yJH0cwMunCMXHg6+LDKxGYqNPg5c3O5fGIlVW4PbU\n" +
                "AfKEorMrFq0qDtEovShUGYvNQSDgXcnlx0y+2qjFwvvIutrvGJzaK8QkX7pmMSID\n" +
                "DD3xJg7hBcaHbl7/2V0Lf9+AJOrFFAXBv8O6ZytPBsupbUURV97C8qD5087w1Mp5\n" +
                "xlk8g/O2hv3zDQwrnTD4h5Xwt11KE1H2/q/rxwpNbX3zcuPKvFMH8HGqC2B0Wt9N\n" +
                "3hLp1uidXGXCn79as4PaAPoo0VeQaamtz7zAuoHOOJiOeAo30kRjtltoet16cJEW\n" +
                "+oTyT1B28lLFvyKuKsgx\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPCertUnknownException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Certificate status UNKNOWN"
        }

    }

    "CERT_PATH_OCSP_03" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR3MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE1WhcNMjkwNDA5MDgx\n" +
                "OTE1WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoFLON9/GQ4AvamHhuplTNcuCyIHWF\n" +
                "Exw6EEvxPjLFOl1wIzCkgVIDWs8xGQbyG0uB5T2nT20ubvMd1uRlrWh9ZP5PKG33\n" +
                "P9O6Bg9ltmMfRIeiVFcJaRgvI5ZmIRWQOzViWBFaabyjQH189yYPJetsGeePPfZl\n" +
                "doFHJQv/ROj0QhEHJKjJFXv5q+i3MdldWaZZj68lTAWokL2VoPmJG8SNTNaqG/Zw\n" +
                "U9/ykS9aY8WA94OlJeaf7SrLDJ4YbpW0ILiHI0QLdOVowJjCwahN59DRHRR+hewS\n" +
                "Ibh0PzvLLYf7YoA52krnSG3nHi+Vo8x3x1nH60oX+Ab5XhM5YRiUxmsHAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDNfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFHc9VNab\n" +
                "ufFhB3w4NtiGo27KSsOGMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQArn+0b41Nkw+3nkGF5zMhL5dlCXoGuA34L\n" +
                "Mqq4uH+iyevmzwe/cEB0YGkFP7CfcN4513EkaQh3VH2eAX5p1SokaRjwBod29HWZ\n" +
                "AwwzCvJ5rJA7Tf2GZpuCrESrO7DdsesLQcFskuUao9kO3Pn8B8vf4ZXfx6u2N1iC\n" +
                "LUtZFKC6jtLw/Yi92m/3Lbc/md9UnjT5Q3zqpJFj1dSgbSBNhNeVSNkj8q0YIgdH\n" +
                "I5J5Q+A7xJmaAbH4LQkAqdGMN3k9ZJVk+8PA8WbV1X01xXV2jzM8aXR+s3rLsMgg\n" +
                "1O+Ri9mGUX8tsg7qX+QsbNDJMKTtr7GE1s0vnbo5KcqZp9Kh3P0K\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWcwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxNVoXDTI3MDQwOTA4\n" +
                "MTkxNVowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwl3aHD0tEv3aM+ZofxOFlaX/DYMSwnplE\n" +
                "ZV/eigtfvC5nyTQQOLs2f5zD7/iLm/wJCgc8ZbqY0YWDpu4en5wgo4HyBZD4gRgS\n" +
                "f+sMZ49t/DvR99lMPue1BU/cm/RRz8mCFsL79ZyY1I8cxSTDdN//i4KO1INlOPtl\n" +
                "6UuWip3kxTNY8wI9pv2ZjcHS939WZyxTfdYAQEkxQuy6oIhc2Un+Ltes/Q0D3yNP\n" +
                "E18qPVTTknuOSl6UIktrhZBpgN582r1U5H7P0dUie2rAw0LWtf7frzkGyE+Z2RJZ\n" +
                "SOddXHBrhumeuGsCuzsTqaqFmX6Eflfm4IQil2uer4KSW4odc2KtAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDNfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBR3PVTWm7nxYQd8ODbYhqNuykrDhjAdBgNVHQ4EFgQUFK3IkEhYhxsc\n" +
                "abEHlT9KjXbHSCQwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBo\n" +
                "o3Wd2KdOVUVN23UKvLay3+I02J21uGzIr9E/saaptf3cbApU+6tU24cbMer8tNdP\n" +
                "Tp4iolcVec41YTE51pL4DkVCQ7lKnthb7/MH/usfcGruby7RLJkzRsleADYRPEZS\n" +
                "uqqN7/hmDaRs6WTQHzP3jrfDpZVljEVssCQz/3L3iGZaC91258ysEfzeeNxP4i3K\n" +
                "lK4lkvWXx229ClqB0GzN0kEiyAW8LO9JpNaohIYyJnHyQRFxnk/WbOh2scAYet1X\n" +
                "OsqwM4KsdOpODH1yNdF5No0VPJ1G7RaXWtFC4gQYzCNl4hlYZDHHNEFr0JDfKjJN\n" +
                "rr5zwqXuofsyU61MZOoi\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPCertRevokedException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Certificate is REVOKED"
        }
    }

    "CERT_PATH_OCSP_04" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR4MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE1WhcNMjkwNDA5MDgx\n" +
                "OTE1WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCauCV/SSnxphb+DKWrcJEeLFhhovOq\n" +
                "ZDMeG5Ya/mHRBreUSBh+zBeQ0YV4d3gRfNEn8/K6gQkhRnCMwXi/jrNzT+FpXR80\n" +
                "SppM0EPJL+ZpS/Rg+aUMxI24caTDVpfIPOa+VYZFwDTt1XBAF+3z3pR+TaCBqosv\n" +
                "ujaZ4Jhp0mM6Q5evdD78EfRSjC172Fs8qQa02gZjPWeClHQbtmubyyLKUYdH1fni\n" +
                "GeroK6haM0AF2xPcdW0gQpEjxZ2mPMgQBvcEHihlZLGshGERk+KSyQfyMWd4D+i8\n" +
                "ECnm1f9X2mg76cXtCxRhvMVCht4ADcVUMYvJ5dUVZTSpAlhBzAvFnhCnAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDRfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFOfhNnue\n" +
                "RSiHGtEwZMlXVSqr+J92MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAtNzbHAtt+aww53WUybm8qoMtyceu+x7fZ\n" +
                "dGWVM/p9KlCGr/IOPmynFn6qTaymBXKNcUi4uQ3W6YAjHbY/Ud4XVxGZCAvaUQxu\n" +
                "aMgXZTNpXBdG14v50ZnG0WWP7QNc2qqYdRSns+BKb3eCekwIQndULeviaB8BTLyH\n" +
                "Hmya4Lr6ItaHG28o0c3A4BILZuWkfXEjTMlYBoghNz/dUq6Sf9h2xAdwZBoypv/j\n" +
                "jGTDLaHDjd5LpXJIrw3Modtmc7bMLaED6C2ZnRDi2cshNG0iAiahai7BNyQz4iIM\n" +
                "TVINSMpZIF8w7IJGR0qUB+z6tpQmhPxZ6Clq1bLFokhrXEF+H9k8\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWgwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxNVoXDTI3MDQwOTA4\n" +
                "MTkxNVowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNem/2J8CeZku9oxIPiIj3k1ycmO4anPkl\n" +
                "h5NhJ5v3zwJSgiZYaOJLJWrkkporlnKGCY+5m0jDCEwer+87Kw1J56keVPFvM7VQ\n" +
                "PP6q0D67lLjU3QtwcKyyxTkCbOonWp714nWg7A0F9IrghDPfmZIFDeWUEaCK8tx/\n" +
                "nnfMIErQNf0yIOJE3Af9HHE1rlPbWut9X/2oruNNCdsHQqOBbIi2m5NgdPoUSjp/\n" +
                "uKbDks4u9IHCXam26KlULb2KuvWU+L3e/FlGcLi9dQV5i7aJdS3GTiuBW1L1twu5\n" +
                "V3J8cgT42sYjEXc0TtyEmabixaz3lAdYKSJIPGFhq1yLWuKm9495AgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDRfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBTn4TZ7nkUohxrRMGTJV1Uqq/ifdjAdBgNVHQ4EFgQU2XXbbUL8Clo7\n" +
                "in1LIi3mhTScHP0wDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQAu\n" +
                "CKrpTUvkssmQROJwCkD8lbXusyIVPd86m+Nyo1s+BbB6QpUgz5F2ue04YFx8hgXX\n" +
                "YY0r4CwBn7rl7pAiD58A1glTqgbgNcgFzNGSRKyGqKo8bPpyPMqNhgi1oqjDr+tY\n" +
                "bETgzv4Z/uPmf0A140KUYLZVzZCEY6z11T0/Rgb+x4oi0y646h5a75B/K+pIXGLR\n" +
                "tPpdnh8nsvbHT/BzS+LKRJJ3T6AItGLhdJPOsxzRN6KcC48HVMohFAgD1kRf7yev\n" +
                "ANAzuNmc/kYAjiDErTYKzTDG9La7k7XavXuH2s2IHJGlqxVGNIiH8zVPr74UQyMB\n" +
                "U803rwzLQPgXDkTUu63T\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPCertRevokedException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Certificate is REVOKED"
        }
    }

    "CERT_PATH_OCSP_05" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR5MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE1WhcNMjkwNDA5MDgx\n" +
                "OTE1WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOkFOaPckId1JwA5YjRTsETAmgpyRf\n" +
                "r7591ehdPzzRaqZJhr+fXlVoiurI8Evwic8oN0+65zkEqTtEIbrBHOYA2nTjpXUV\n" +
                "HdGsbIq6+RxMuksq4oIka5CLKZI91JDHF1dJZYluJ6IFPjYb3UiyLc+OQadxhgQW\n" +
                "WFVziP7Dm+5xeChvxoQupCdFpKs1x1pnuvvryC8YxDewTHO0n+XG2T2zXSq9yTTA\n" +
                "rdVT//Wh6HjXH77aCGZ68yKVOmWj6RZcQwZzYqfMzBM5ZTKaEm/1IXo3XOVrGTVJ\n" +
                "/aB2YEMgiD+4E4pnFvozMVVWAkowQQkbC8vaWIRFxBOop0XYPt1bSwxBAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDVfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFJ6Aiu0m\n" +
                "d6l1hssXYpAMIg22hQ20MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQCh4qt8lieTT1UOmVwFw0mcmJhZMFihVpxT\n" +
                "MGyXjxFENaitQoOG6pTrcAa2cVy+TJIYzqeAk+P0+rbQIsMQE1piFiMLH1CKmnU4\n" +
                "5XgoqOtyHLvwuBQj9V53Bt8ndRaDM1/hskcHI+cXvvTcnpu8YVJ4l/WUffSgW0tk\n" +
                "SMN6zE5VC3Kp9VKxury4sFnWK+ihNlliClrcab+tT312pZ58CGtVpwWgJ34doYYq\n" +
                "t93YhuH/InTfDdL6UCaBktY6AMJjNWUr18nijlI650MbwjEavpCwUX5y4IV6Fq0I\n" +
                "hpqr7gSu5Usiwuub1Bld/OR53KJAeKvSGhg/Hl+w6xwqd8A2nHQ/\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWkwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxNloXDTI3MDQwOTA4\n" +
                "MTkxNlowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXuRECNA526rM2g5+G3tCcu5zIPXvY0r/c\n" +
                "MkffddwZ4pAQJBhH/5pRlwcLAVcgJekyfgEZ6PW+bmSBo4IkAP58vg1xvnJFAbi0\n" +
                "6nCkTVtDVgxJVmx8vYVeUY28WYnao3GyffpK5mQFIH1tGg8aDgKShjmsyT8c+crj\n" +
                "nXrV4Ey4erd27I1A3+Vx/4/dsfRaune6n0WYge9w0bKfCFN9tQl4BptbEhkj71cr\n" +
                "VAA2Y46KKwCiam7Fr4Ozw5bhgrI/QkNiLbR5h3bvK0Lz8iyOXusGMAcIhxHg0JMi\n" +
                "uur9cFt7sJD+c5FCwQ3utSRF4ZSZLvaNEj45uIbNbYj3+B9lyXkPAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDVfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBSegIrtJnepdYbLF2KQDCINtoUNtDAdBgNVHQ4EFgQUf4Fs3SUHS5rQ\n" +
                "fHgmWsbHJalHHjEwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQC+\n" +
                "oQeKMZmYemwt7j5kiAa3InWrWSHDZkBjnMtjGQxijY9P2glXrRSIFENiyYWSHNii\n" +
                "EaJ9UeDhbzBPcbk+4WBpGRv43pqgy1vvxIJtNCwIz3FBfakn/tFa263Asyz00asW\n" +
                "ChSolxoOKsGugk6SkgxnKcyFDnSLgFJd9aWYKXG6UeJvhjjiFo4tsJu51LULI55s\n" +
                "3JhFiQdvZEyUs6Zoe38RciNPscqlPWAzrw50S5kyRVFyX/aKWjjlHxoW5RLcTCuO\n" +
                "7mqwH3iGBiphVGecnZrZJ8JrmsM2D7POAT3lCLNpnRoA3r//6HNihDerQnPN40C9\n" +
                "vv70dLTqdEKkvCwnN39r\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPResponseSignatureException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "OCSP Response signature verification failed."
        }
    }

    "CERT_PATH_OCSP_06" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR6MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE2WhcNMjkwNDA5MDgx\n" +
                "OTE2WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCLZj/brn8jAtf7F75PT23T67NfUoBW\n" +
                "4wDeOhM9Rkuj22SAlTSCKZ+DmEdGhjAm2TGrwt6Kijr6cyfW4Tz3P0QumBjdGY7U\n" +
                "HsrXomduppNiDfecJ8eVnJPGtiJh1h4MZINrloSvGrv7ELxekhmSKh3GFKZgq9FY\n" +
                "ghcoV4I5NCLfQad2Ouxwy8YCwYcWcvW45pFeX7s3GjTVGgJMkOq/EGyFwbF528eN\n" +
                "SmrzOKl7UFI+vKjV23MA3w/JcxB+F2UZ7Y5wlxRumNKp0Yo+abhHQKiGrwUDcT0Q\n" +
                "AQtv9vRy28yPDXNzFnt+X+RBxtELsIvj+SFEk1qwDnINU6dm49UNdRuZAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDZfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFBtv7Iko\n" +
                "qAojU2oTr2KMADq0Nc+mMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBLlhvzYvmJZ6P48BPzrw4vX4ym2Hogbv0s\n" +
                "g/yq2en6dezi3FrGknkC5PNvr5DVvKhFr5nXK6Dww7uwogjUq4Y8J8dRO4vt9f8O\n" +
                "vF/YDIpS/OtzKD74rgHEbxrVWo5znOzztfiiLwIeoVH0W9weowrO0ASBqS5LXgBN\n" +
                "Ej7skxVbu0DiDuE6zEAh2lnY6KHeovcRdGxlnx+QskDjHbzJ15cpksk4VhepLZAY\n" +
                "sYPT3zCATz0Wf+BgwD41TwQm15v8lcNr9lSNAW55+dTnDHFwTTkhQM00kvj/QIZa\n" +
                "DKGeSVKjkB9VJRaOAX9kguhts+XaQ9jM+jqjXTWCsmUTrTeEKelD\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWowDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxNloXDTI3MDQwOTA4\n" +
                "MTkxNlowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDF8uFW35Z4OLa2lgRstalzsg3Dsic8Cl0V\n" +
                "fxKg7pJxa+HUdxNZeqv0bntWy7zmxoduIjwrL403zd7NHyJUW7IT6dE5+LfnlW0F\n" +
                "k3d8A7s/dxoq9VQPIdULeMXfDwzrEhYakyw1Gidj0WbVnr+ikeElx8BtUMAmMnyP\n" +
                "jui5Ov7WVnyNPhA24oHRCTIhLME3RmQistFXEBsql2iNefAEprlhdw5P8m1rCx1i\n" +
                "ftYV6GlLBhIb+xuOtUsQgwtx8RrTAYKBQV5YmYQ7JYJECHrPRHD4nRj6rQ01T6XS\n" +
                "HS+3//1x6xmSog4zvaZK+O4nHFL66QDsETUrp82zVycTTWwhqvMdAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDZfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBQbb+yJKKgKI1NqE69ijAA6tDXPpjAdBgNVHQ4EFgQUk36L1y7TdGc6\n" +
                "VRMmwpOr1LDY7MMwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQAv\n" +
                "1GGam6pMkpf5xrgBqtKlZn1NoUKVB85BP8PY+cDNf3wIfxohOK8/LNNf2eskxyU9\n" +
                "w51O4bz4R8zE7yENE3Ie6++EPaBuiF9JXxxTiZ71CavOu/RsTGsY+FGTh0mVbc1u\n" +
                "RedhZIbYIixyk12fsemIt8SLmjLLY4OK1TwSRWuaBs2kbq9/LEA+cFPDzBGBo0BB\n" +
                "DRPuvXB9FrVneN6GmeiLNS+j2tnnETuv0jnzjpHSpxLaugYug2+3RCAmeBbbAzIW\n" +
                "gdcSa2/gktmtj8j84MZDn+TDuC9rl57obrnEf68NzsAsmIHwCXgSQNTKYX23Q4m4\n" +
                "LpPdEm+Sj7nwJjmTaxxU\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()


        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))

        shouldNotThrowAny {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }
    }

    "CERT_PATH_OCSP_07" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR7MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE2WhcNMjkwNDA5MDgx\n" +
                "OTE2WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZym46G3iOoUa40mx/ZXO7vouWGN9U\n" +
                "pIU9FNzLD1J8iEIQ84tP0SILRVRSHLlfaO/wJ47soeO3FerlXa2LBxBFua1GUS9y\n" +
                "BBDK44YpEpMZXOaN9W9/tEfPuFIdIt0zha01Kbnb3NQC+evwEuyW2fMMwZsrQ+Z+\n" +
                "vcH0wWPcNgZX2UkwU1RW6beFvUkLJuxu7IA4wi6AhrBH15txRiFf7B4eA0wrD4/C\n" +
                "yB+h8kkqEJl1ixByqDzd9Ln92/Q3BcUTTqw83zhx7piKN2lxiTT/z3WgLy+LSyOu\n" +
                "aj+qX2l9LTZfE8xLf6yLptd69xnhU0oeAOiqumI789Q+ZafU3eU08UW7AgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDdfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFHn4o4zZ\n" +
                "drzbrF2dxa7kKvlYF8scMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAXIeOHSUpLaUftj1zDlmIMSsblFgdk8lmy\n" +
                "E8M0GsDCp/8QSxPFfE2gCA5gpjJxM4/iPwX+54CcrN5MwQvxhMpeACSrNp+lTb7H\n" +
                "DecvciS2sI2i0XKHenXx+8uMq1y7MLc95w3HPfdYCLGLk88utNe8Jg3XnBLv9Q/l\n" +
                "aS0fAPTWSsIeZE/aog8l5TymbBe5qA1AF/5W3hSjPf5ULvBH+Jts2Igm5u2TIVMN\n" +
                "K4z33PLTjr25W/lkChoUJ2FKbwBP/LLr4SzPlW1axE189mXsWeplntj6Onu1cYt1\n" +
                "g521v0Syw44VbabN3fI2BHZWxwCnQAml4LzK2BKGHkHo83KUxOE0\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWswDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxN1oXDTI3MDQwOTA4\n" +
                "MTkxN1owHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpsKDRuc2gHB6MS9rGJlBUHvRpNszW0CtY\n" +
                "OFmIDN1C3ww+WlRyuTd5ZYB58sylb9gNcOojzW615tAT7hbqdguv7bqciH4lFBW1\n" +
                "tNglFmlCSLFAPWhqieD51eTb/EcBWjhFtd7ZE98HGtjbik+l79Q35OC7fzUdP68Q\n" +
                "U4OnEfik/oFibKISiKgys6nhSpUATWfWYeCIgkeMcTJZf0C34eAmPpN9p8p6IGzE\n" +
                "Y3cdp+9tacS1BgRUObyGNEAGJImjvVKobHJVIIGJCACVr21+MS0W4lqqTXvFTZ2v\n" +
                "xFzVBlzBcPle211qeQPqyPPW5ICF+9Y8VCzMkMn/H+A1Tn/b6iXtAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDdfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBR5+KOM2Xa826xdncWu5Cr5WBfLHDAdBgNVHQ4EFgQUqntC244IXgha\n" +
                "/JOf6f52X/0HbwowDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQCf\n" +
                "HC6Z+K8GimUFZytloX2gMmH4IueiPhVdpiGKDE0gh9LieiDNJJ4ZhX4vfo9P3flA\n" +
                "djv9r8epOa7qBdjrOOL9zxIjRHyWmcEGv2DyiDR2+w8Qm8KndvkDkut3kASmGsnT\n" +
                "QoUU+ZrgWsseRi3qBahdwjkDBOnmzOBMekhQZUUa6E1Qj2VVjidN3ulW6gbnKaDd\n" +
                "6d7FFgAx99hhU2bVfya0IrDXgBBKAGfyacC9RDBRNDzoTFG54EOzv/q6zpC86sjk\n" +
                "yqP/BIQHcjQlcOH3bJo5PkACkyh+ebiXgjyNSIs8XKcLAgUyWNg6JQ5F033w+uz4\n" +
                "TrFnjkjbqJLsVP4gjtW7\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPUnsupportedCriticalExtensionException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Unsupported CRITICAL OCSP extension: 1.2.3.4.5.7"
        }
    }

    "CERT_PATH_OCSP_08" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR8MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE3WhcNMjkwNDA5MDgx\n" +
                "OTE3WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDL9lkx6uQ41ZXGHvBndkxDbOwVpYzv\n" +
                "QIaST1H16KHr7I5QtOw62ZQU3MS+3WSfsyvf77n1ekm18VLRLYta8Nz2HtLAIcFD\n" +
                "IerzAMfEhodOG/nuT3d/qEyP2q8mv9FdTRy8t0PK/h+1YUAQHaEc20BP6GDt/zW+\n" +
                "yKTmJCYweCw9kbpEp7IQVPJzl9r1a9QcI6ESLO+MywkxpDdfku9pu11KScLZVuHF\n" +
                "TKzXxbt8iPO+R5lsMrX8rFLPs1F5E7D5y+xE5IdApb9ZYm/mQUSittRGLFN0gtUC\n" +
                "/TsiaNz63j5MbsAf/US3iZzoolllO++1QWdHDFbA4oc2f5aTHzJaU2mXAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDhfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFPmG78pT\n" +
                "hVsyz4syBGDFpwGFV1ZkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAvHJzGEidBFoNv3mFBwFNY7HR6xERGy7/7\n" +
                "hzElZyCKxZS+RggrcaEbNBZf9dK4HjFAqyxY97/KFwwUL8NqJBNGfO0dDlH6XZDz\n" +
                "QrAecKlCEPudG/NgEsxYB7dCGXSa+ziH+IX0fJLlDIK1jCZ8f2gXffNirL8zT76p\n" +
                "UiHFmzluSrYpGlBvRZjXoc83nX9JcZ/irDrFbEQeDRcXige7Ebp1pFXqkVsCDUjU\n" +
                "c22q3/KbEuPjmZZLW/eLYZ7ram+m2wkrSFpj3E2Hyqa1VUvfdvW08LAi46ULSfwr\n" +
                "cIy742ykG13TqCu/Mg5TjwOgyU4/GtbFOSYwhGNFaDpFuZOPTuDW\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWwwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxN1oXDTI3MDQwOTA4\n" +
                "MTkxN1owHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhb2UERufXmzYmhH4LlGTHwjnO+EjWsO8/\n" +
                "rKhoAabkl+HLiWmkD3yWp5YvIZnxwZeMNS547WEWFBWkJFHe2zkgjVqDN+WLyQno\n" +
                "qrP8nikpU+fDTroxa5aXa1hWT5gPmjIWtcTBY9VsGwcCrh+a5unVPAAfxlJG+KHM\n" +
                "vQU0OlZzAqmoj3gU5d+tgl9NXWdwSDL9jHiA+ss/WS5JL1qSAkpcsVRGsQSNBkNz\n" +
                "awVjWCXUyzpmpipuowyEPt+v7PFTWv1gMvt5jm/ExtKyZD54PZbA+SdRBq5QUWAh\n" +
                "59nj7/oiOm/BzgAUwBaQXFqV/V1cevrVTblVsGTpwX5qJXtwgUSpAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDhfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBT5hu/KU4VbMs+LMgRgxacBhVdWZDAdBgNVHQ4EFgQUJR/rpmrU27+5\n" +
                "iM1ljlsLzSdjcC4wDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBs\n" +
                "nIGx3/L10XbYr5UD5j3wVZn9m9Kxcc0KLO8S8NN2ipvhRBA9kwj4H9NL+qR4ebrs\n" +
                "IHAnwtpZsXA3zFVz7ofkE92Ywsrlh7JRlBq5IlAk0T6SqKfHoQDnGWW3PW2h4Rw0\n" +
                "YyUB+LblDpwddN+bb4ZYesFSdZImAYzFDEZST7OHmSy9okqH33Xg+FDOktGdL2U6\n" +
                "RE6WskVsoHTH1dbO+mLkHroQdJRY8b5OZwOTU6ue4oBQzXoi+RWzvWWBKy3hpRY7\n" +
                "OKnGObpc7tXHouHJM6P68vDBUPnfJczEoAu6IowKN9IBXR64IDt2+JtA5mo3WgJB\n" +
                "aDblfO6Ss5AX3vwWnqdI\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPNotYetValidException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "OCSP response is not yet valid"
        }
    }

    "CERT_PATH_OCSP_09" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR9MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTMwWhcNMjkwNDA5MDgx\n" +
                "OTMwWjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0NI7Zha7MQuN7oCjMMWVn9UV1jgVI\n" +
                "DU2+byFTWhjKaFgPpAOsebvVigSqn1xPvRS6KoG7VGG1WXKHBf4BduDW6hn5ppyk\n" +
                "baGjkq3kCiMn1sS9/T0u/FKRibD+aJkJScDqzwjBaq98atN60uhEXQXvKmx0m19P\n" +
                "yZNkjc8omRmQF45ZT+wsEtaLkyY7FLDIHT5fmDWPLFKtvV4zrTl5Ly8wj84K1AJB\n" +
                "pG1PfL7ZtUTmMGD3PrwBvgW7S71rC7p1PxPnzouUMZk1mvenMIBMXbasNO0rOZ1v\n" +
                "rzwMCFEyJV3EWshGJprADC4TSHVNpaP3mRc6SHKYie2ES3f1gqHoFEI5AgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDlfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFE0wPayi\n" +
                "sEIZ1aokilT01OwBlyCmMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAdmQs9kkjbG9Tq8zGetTyI7sYoiavGJMAa\n" +
                "0mvhfJEwFNByRW8I8hvaKLN1IygE5UzqW8EvupfAfgqGqNczCuPoV6x/d6NHe90y\n" +
                "Cy2CzAzRypNC/i2d39g96HbtGuKuMAAkk4cRt8/W5E7reH+b3+rXUN+hCIIRf3nr\n" +
                "ye8VU7lcvTj1G2mYzEEq7e8AAqgY4kZtLThNZUKgivSMnkN52tmxF4BE/VuohMxL\n" +
                "xwpuH4+RB0G9t7jIYlSWwSxZQY/usgQMgqoxzrIXIc24SCd12I+hCNHKySwVQKHL\n" +
                "OzL9+jq3L9KqPsjbPrrAY3szvnZXvsENAAPQ0pfW+0jRQuUfP7my\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfW0wDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkzMFoXDTI3MDQwOTA4\n" +
                "MTkzMFowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ6omKX2xx7xZQ9XFQMYnl4d5biVZ5n/cX\n" +
                "zF/AQ77Yn9ccgqU4jr1WVOROlGdSF1dc9kWUbdDLRRhxCWnMwb0TDXRxiKCyTa/r\n" +
                "7xBt9CGFf9vWIYbrf67pg/QQE3jIUQAzSReyZ3M4FnhWMmNi6TAPQUP86rnz8EZ9\n" +
                "TdJPPWBpRnIz71KZzLic6VpzhM4FyxpJ5oaHLBMe9N8zrEp9/M9hNV7sDLN54LBC\n" +
                "72BTr+XJsCj6s5mYm3Z9ibRZ0Wq3eUGoAyYZgKQQ8oPK4G6cPqOOe1cKms5GitLK\n" +
                "V6juneLPgerAORE1eizHFPI60sbDgPNx1TLH+FZskVQ2VikhabUNAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDlfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBRNMD2sorBCGdWqJIpU9NTsAZcgpjAdBgNVHQ4EFgQUPvg4E91R6GiO\n" +
                "P/3MhhtjR1N3t8cwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBw\n" +
                "myzb5rrHZkMYG5UQURFpASjmsn7WJo4spBRhlwnVF9R2R+Sm7rca8XhAojr6Cd0c\n" +
                "TasvlAr7abY/CkY3xS07mnJThvFMqJMZnb0JhZww0kEG/HkR5XxsMOb2Oxs7NJ5m\n" +
                "BCMqP5LmwMtRyAARJkDRoKjUQZ+xzVpdieAbOpanfPx2K9g9ienariRCjd5aqj7i\n" +
                "hCOx0mgP0ixtMb4wSexKCA05qEJ8bOwIWXy3cfViLf2kJwg9JdtLyeygAqxEWucB\n" +
                "AGDjcKz+ouKk9G81W9u0Gj/IvS/1ESlfAxYzXKmoT0YQN0ISmtflmT025ssnRI5I\n" +
                "l128NMyuaHquUE1Hx/Rc\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPExpiredException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "OCSP response has expired"
        }
    }

    "CERT_PATH_OCSP_10" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR+MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE4WhcNMjkwNDA5MDgx\n" +
                "OTE4WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC30s7ecxmI1Hp42I9u7UAuL33yih8u\n" +
                "R5VcoxHid4S+0MRahi1RW7vOjiwLMPXZYa4vuSKIRUeaQnWcU6RJDCVcxxKlL+mc\n" +
                "Px0dXxKBEdfSrgW31+08peeFwUhJCFLMNMGXeO/TuXBnuFFjjk8LnLuDwWlgwiyh\n" +
                "MX9xQ3D5NCTSkCH09Ckze17oANsK3fF+ndWGzs2F4Doj8w/euICCPfmpYRYB8u2Q\n" +
                "x/pMBMMUsvVn3CjNb8G8CERSW5O/1Y9CXgSnbwqacDqQ/JDgouaBSL8/X8VjhpmN\n" +
                "rP7f8JuYEPbhU0VOlDWqSa59A7p8J5B9Ejnk3vllMXit+DIrYfhLL8rfAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTBfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFGfd1wWq\n" +
                "3FnpM2cus0Lfr/+449eQMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQA8LyKYzH731WBf/ZXXGYTHf5Fg1Sn9su2v\n" +
                "sRcSvSjJ1CQ7fu96rtdEUSWNY+i9lTAuAl52z+bbvfQu0IsYgWF95wc76NxpKGfI\n" +
                "1vXTLITtw6I1M7+HQNvyLEdmP6Q63TLZBsACim1+Iq3zxO09kyNpvfklhJa6OyE5\n" +
                "FS2WJx30WqtAeacSh57PZsgsVZ2qWnyqWHtbBernyAW+tYEvkrbtHJuwgv1M8nVU\n" +
                "cW7BcWwEyMXOtjasfKEA5xJeHDb67iotsEDKHgCJxJTyu/Q5KderrCz21QBRa4Ec\n" +
                "w/C+Iwt+7vHUlptX1gOiiUjhBIfWUhh9Nvd/kUPFOhrZztPoSGAD\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfW4wDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxOVoXDTI3MDQwOTA4\n" +
                "MTkxOVowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2KdzUD2onh37Vtk4cCNFaEo2Y6jAtCPmj\n" +
                "QVBNEkZtcPMtP4cGgBDhVUvZEV2Xo/BSQtlHzKcfXxSX353IU/P/biDw3fYY/De0\n" +
                "Spk/2R9VOE2EBcACgXrkeLPTA4pLMo3KEXHHAO3FjgCU/5HZr+xb3oApZhFQPKnS\n" +
                "AgHrabQye16rv/y1rVfWLfa1zNxPyraXgI70KfX6JCSWTfQ/a0ztMCK8dAl/0JyO\n" +
                "qjV70v7l8ozSo+BVvKWzwtI44uWpxXVlFmWtbULXvGWwWix6iDzGEQi39QZ/BbAt\n" +
                "PFJ9MqdyXWwY6UY4hIJhKOs8UU7tkbYXTJ/5aZ/Nbm64bO867oVhAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTBfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBRn3dcFqtxZ6TNnLrNC36//uOPXkDAdBgNVHQ4EFgQUJoDsDPPNC4ta\n" +
                "L6mtvd1zWR+6u04wDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBx\n" +
                "cqNdcDEzOiblyvhRWEXpDFr0zb4ddfBR1SmoKWDVi05rUPsFdlhdBRF4P5CNAtsF\n" +
                "bCd7NSIG0/HFYOT6ILiMd0LWEbthg9PIYeqrmyHoXH8VYeg7hoUwURv7FjBd9JKu\n" +
                "vKmNigFMtHK1QS+C0bV3XMoeoFr0zHsvHTDWjYvOtySlGYHNAxrMqD6rUMO45xfY\n" +
                "y0Xp+vqpUoTX3zLYjyyklKREtDmBMB1QqoVShW+Gqvgz/+q1wNqL+vrsf18lOptZ\n" +
                "ZHFUXrkZ+IOylEzxs2BG3DHCgvLtxxssBLa93h7ZuJSU4uu5bQRCZkm1BXgUH7tC\n" +
                "j9UZGnIN/af56mmmvjMG\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPUnauthorizedResponderException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Delegated OCSP responder missing Extended Key Usage extension."
        }
    }

    "CERT_PATH_OCSP_12" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSAMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTIxWhcNMjkwNDA5MDgx\n" +
                "OTIxWjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnTPFxN1UPKtJgIr3m9bT0d37nrldH\n" +
                "PeT1QsoibIVga3TowEO3fsG8du1iOTGAKqrQK+DObFZJOE1BFhGx5+6owx6dAge6\n" +
                "1B7fZ1X87iQVMJkiA78tzlG9AxUJx333Y4BBB9v9oGBoQ5h12up8NA4wPaYCfPzz\n" +
                "N+9gQiGz88tVDHo+LYeeoQKNpsfZjxsotJAKYNUmM8GGPFRUHmEUNzNZdlJuyjvS\n" +
                "2F6LbhIRsvu4/MIAPolXMTnzNXEgCbPURWaSJ5qIFJH1Od44DnIVBbX3mTdMg2n9\n" +
                "yRoSxg+BCXlfGFXwG0RtSJdQWh+PlH/8LTYI3yRfbef99LU9fljS+OPtAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTJfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFOAodqZh\n" +
                "jFr7AimWlz8PqrqPEMnWMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQCcwr06BKI1j42bNSf8VnXPuY12Mb86s99q\n" +
                "vd7wBSrZK5v0mUWDA7D8K7ZDk2/LKO0v6gXXzFeS0jMo+DHfziU78RPXbK9zfp9X\n" +
                "hyOxN64HLuXOP5zEi4QuxupB48w09Uo/ZzkcV6QZlmw0yt485OSV+3O7YfCcJrdk\n" +
                "aNquYtdecaG4cs7RGnBUqCWtsjI+E0dyzxDdB1eUg4NHs4ml9XLiAdcHGvUIFTcG\n" +
                "O8vMY44ijrz1KQiv6qvRTry+YxDFCQVOCuhpJ3ZRNgj0akdG9FgZy2seZmj2cl2x\n" +
                "27d1ZlNV5m0TSYG0elX+hByB6YXTY0+KgD0uwT8iyv6JOIhWWGW1\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfXAwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkyMVoXDTI3MDQwOTA4\n" +
                "MTkyMVowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmwrQEP/OvQl+e++bTEfcUcbH+Frg3oOm+\n" +
                "eMhVySlZFv1+6AKlXnxk1tDVdUYo/Nqgaxb5yhhUR2c+Ikx73Hr9e0pviaVtdIxH\n" +
                "jD5OH4uT/3Nnv0wz+HzHS4Wvl2fjOETQTLiXownNyLZxBSw9UXrUxHkkYAkbK1Vh\n" +
                "EGnbmBBfLRwhgKKmPDXvK2h+D0Q2BN0QrnAhZ2M7s0K9VhCQ9Tg2i7XWt8+MjAJc\n" +
                "sPZI/XjOk1r/zc/hYF1peB8KSIlPsPTGXKTiFxlnl36hLZTsbBwyEPRbN83KiKlR\n" +
                "pBDBl0la0bjp3F88RzYd4r1s6JT/oSJqyPQJ4Tko8faNw+7WRC+dAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTJfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBTgKHamYYxa+wIplpc/D6q6jxDJ1jAdBgNVHQ4EFgQUGE2xJ8XhqzNH\n" +
                "DCba66m1Lx4/BwswDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQCJ\n" +
                "nwcPNFNAtsEY1Ms+uTi7+LHolQBiNXqGGc6n94J0wyzm393J6DoR131JceaxXCF6\n" +
                "DNA//3L4Ec7JjwpYERTJ6gd1Fky16jJaCN+2pt5prls76Sei12uOAOES1EudiVLa\n" +
                "sO3lZbDQtbaxF7phi/OxhB5bAB4MRHax1wnpiFB0uPZNbeaMOdq2CxhlfZrhI4P7\n" +
                "CLehHwgn92PyyyyGEi6qqauISbK5YW+P+rdpvJmLrgQlqs71tQkJEOSkJzSr6vj6\n" +
                "RhzSUghwbkuuoAjWjY85wPh+wGaW0vxm71uhYBoq1vmDI4DrFQpW4CV/+fEQk442\n" +
                "tuaEiAOHGZ+x+v6WDLDh\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldNotThrowAny {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }
    }

    "CERT_PATH_OCSP_13" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSBMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxODUzWhcNMjkwNDA5MDgx\n" +
                "ODUzWjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD6x4ahSwrHWdfBiAICj/uhHOl3WMof\n" +
                "pC1VkL27DjuYnWjkt8+jiEYaiDyDUoyqypgOI2VmEAITx/OjxlbtDa8qmBIf1nhZ\n" +
                "aVy7OIURZx0PNLHA7k298tb7itKsyB6hHC+sBIaXo9rc4plWbQtvB6usvYqRzMdI\n" +
                "5L4A3s4VU/JwhwYyul2d+5OAFLkhYy/EOZBJlyHc7bIdO5aL8kRkOj6jv2JF9Wju\n" +
                "38XV6mU6GIPAchUQGOhEysuXKJAiLZQVY96YswP6A/JU3CDNteClpgPsxyrW/pZx\n" +
                "kfEC7cGTPi8tbNkzE/skUOo0jrfC81/M+U3K43Aq+ue4g6E+jiwijdb7AgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTNfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFHy1Dpqp\n" +
                "NFeChoclAPLzq6wmKdl0MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBdsaNgNpExnSf7Wyx1xJkb2++SD1pDfcYN\n" +
                "yt3D2iLhBv16lswuQuTTDojfEZOUvMhjtftV8ZerlNNhB2X5XqX3hdnfMICM2BYn\n" +
                "hAgmSk5CK0V5Z/tBsxJPoSJOzHke930fFyAuUpujkSB9KIrNfl6A0Yigi43xJUqd\n" +
                "vtk3klNzwiggsMdFMHIQe63qwOaW5XgxGULZVKC17MN7iuUqhW09oRGJ80atzjT8\n" +
                "wHTYJEHS7SG6kiVpA42ci6V4Ebxk6P4AcBcoqEGFD332me9vX5J3emKeCPyKap2m\n" +
                "m0jjaRfQmLaubZU14GQnzzQA/K/x7XY4CeTR83mAcifXa+xwx7AX\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfXEwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTg1NFoXDTI3MDQwOTA4\n" +
                "MTg1NFowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCP5uWeO9WJXRo7pbJtiku9GuL79Ck8WJ5p\n" +
                "emOqmJ4LeWInJQjbAK93FsPf5M6izbfrkhEtymK9UuuQtY/kgKgJoS2sQ2QQZtJ9\n" +
                "Q0cGzXbKw5Fqt3IlhzAhhxP098wc14DAj2lA1PHUJSs69+rlD39tZij8eJzPHMiS\n" +
                "RZo73VnE3nda8V9xauVJB4x0VZrVOhZhWEa6oE/Fuee+ourhTMrPyqhxaFsVH5kh\n" +
                "a5JHoHaPei2lVT4B4RF8figqjaSDr+kSxOVMFdAjk7+Emtvxv23lVFgoQwSDQLe4\n" +
                "/IilPJtNIKHIWbNFp+5iDSNT6hLzLPrpLTnvd/g4njb74kVEhnRrAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTNfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBR8tQ6aqTRXgoaHJQDy86usJinZdDAdBgNVHQ4EFgQUJnKwSYTc0P1E\n" +
                "y1afdlRAp+EcT2EwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQB4\n" +
                "j3mSfWt2vBrdKDDniF8qOssP6X6T4PTjbzNKfmyYMTs5450Nc//iSb0sc1lihK04\n" +
                "c/RfT6jGSrVIBoz9aRD0nOs3ZV37JLvt5ExyqdeEFRH5wLjM/FovuFDcTms7DlO3\n" +
                "2EQfKN5lgbQfVsZDRiJPBjlTpr80OvA5JAnB94F2kMXlwYu4IabykriuANKSi6J5\n" +
                "ChdKQzKH4OfXRW+n7CHATGWfskBdDvDWjjlVWnZa0o4fxITVJsMujt7oxjc3+MSa\n" +
                "7mtF+d20YduOn5EgDPKjAGB1z7GvRTuQZSfJuPK6GIc45J+7cz3iapvacdp6a0I/\n" +
                "4tn82HGR+uLtxRieSUiq\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPStatusException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "OCSP error: TRY_LATER"
        }
    }

    "CERT_PATH_OCSP_14" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSCMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTIzWhcNMjkwNDA5MDgx\n" +
                "OTIzWjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfAG8jbUJ9RunCA5E6LivPVQDfp083\n" +
                "8uGoeoTvthhHaFinDwbnlyl+3XuMedKetNBh4FULXsdSz+iOG/0iLzxCxDM6FQw2\n" +
                "1R9NKrDTx9fPSv/ETSjPDXACidn0J1Y9PYI/bt/GnYZv48nY6DRdjJm/hRzn1Qof\n" +
                "4unJTYIbWnDqo6h/eyMbqPBK5EdUoEFQou1kzLjfpH1X7tlNsfPFLZSBwFnyOd7s\n" +
                "BX88WjtRI2Z5ES0+GAdKYxWOmueiAb27l8UtztHbQ3x1ug08kyVFJbDgVKitjHnw\n" +
                "fd2tppR0cH9vZuKZqODYno/NdO9rsxH+joRGQ76o48ZNXZaxj4WIWBhHAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTRfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFH59qVKO\n" +
                "ktF2fq/9D11Qt8tFEkRSMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAG6DQQi+7gNiZcZ3V4eyCjGE46GTtpOKg4\n" +
                "+aJG67rklZdCTuBo1wikBODS8XluPW07hjWq9zk3HbJsKtYD9sapGxQHMSDBRxh5\n" +
                "vQrCst8n6g+AhJe+cnmM2pE3hdWQOA2+ZvBUDErqqqZO/HIZRVyOLvpNzTNjq8HS\n" +
                "B6a2RT5xWX6yZB5kPhTbtKNJEleK2hh1af9VoWXfyga63IMrGbGkcsK+k/Vw2vS3\n" +
                "tMXxPoWH5GJySqe8rVm8hjCXUCE0kbiUDq6AHCm22oUFiji3DEj9q7AS0KXeAYDj\n" +
                "19RKZFk8Oo3ikEu0mUwXKEowA25SZfDMbblRbRbYjLIxGhZCEoiK\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfXIwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkyM1oXDTI3MDQwOTA4\n" +
                "MTkyM1owHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOtVHjHdXJJSlYpQ4K9+FsNmuaUYQms0P5\n" +
                "SBWTmAg0ivncIg09TvB92RssK0I2shJZsxyBL3TEVJXFP57jVUkfRo9H9Jn1Io8M\n" +
                "512I7Ec4T5lvPmit55sffWq3faL5nBEYzN+Q69RO2bT+pC0StjIdY64pxkrnrsJM\n" +
                "kMf9/mc7LUC3nuj595sQzvWVx6NnhOyk9SozwvGBK+Cihny/7ekSaR6zCmIqt4EN\n" +
                "ViNdCaxP0Nt6muNtwyile015Y4c96C2NlKlrXHNsjdefBltMu7tEhFZvY/AP6Qww\n" +
                "biSkMLAVdweZdNZHMhYP7Z2thn2rOdvCJD4+TBhOiAATOeC0/NAjAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTRfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBR+falSjpLRdn6v/Q9dULfLRRJEUjAdBgNVHQ4EFgQUXgh63axOhCPD\n" +
                "FWkPEC230QFpj4gwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBt\n" +
                "zr9AvsSvMYqm9LAIyM8+rPyj7Upto4kWtLHV2pglhlF74hkqYOtCYA9E896qtFWa\n" +
                "yuYe8BaVzyKgmlvv5M2o4euZfE4m550So6H7q4NKS7yarMvwVUlLPESQDdOB7e4X\n" +
                "F//rD5qx2u0y5h03iT+NY1YQ9ZxIDso/A9k0jcsVidRaNBr46aZ+AGC5azTsFU8G\n" +
                "i2dZyla6K0U6cxYGCrTXh7jMYkF212g6LN4hr4Jy5heRxNl4e1D+rukzyekj9dLV\n" +
                "w9HSNZhjBkCReudyEz2By8uCb0/c8ZIT4qkB5I7038GJw2Zs7V+x5DZYWEOZUxod\n" +
                "JKtJfq5GTqfax8NKvgOY\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPNoMatchingResponseException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Responder did not include status for the requested certificate"
        }
    }

    "CERT_PATH_OCSP_15" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSDMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTI0WhcNMjkwNDA5MDgx\n" +
                "OTI0WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZr6UnjjtIm2Sn5cOCWtSjVciCF9f9\n" +
                "nf3pyGy9w9jn2zJhAzWpFWOJdgbhFHUc0bmGcBTWvTOLdnp7btubbziPIsVjcZB9\n" +
                "xlcrYfBR8M4FfrcgYW3isTpBp0DxlDtNk1Tfj+wut5Oeo0EN7kHclIKz+PUW9kBF\n" +
                "lm3h+VuuCQkJ9CpsTgvtfrS4Wtc/nyGYaGf6wAphPb1pBAgIeHgT9mp9XYI9ncpg\n" +
                "H7Kqk75XZUkinw21JLtk++Fiej/8DENzLvxnm8AsPdI8M2K165AVwU+92naKzcxl\n" +
                "28n2gDzWBD83q8b7PXzahz6iLMydRPU8891kGjbHiS9aLSUgUZPYrhY7AgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTVfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFGjgmxGW\n" +
                "+v7iTOsih2TR47cZij9dMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQACxKQmCYGZqRroF+1Ibq9p/JTn9DSqD3ee\n" +
                "ibcUURBiCpsNprQsySocuO4UIjtsqJ9QHHMSkJsELd+V2ulHfnLu6Q+x/9uJsXqP\n" +
                "TpT0iS7k03nNaA9EWqsEyv+UZezHMEubo/yKWnwPcw0CMHSSL5oLFOWtrWy4oF+h\n" +
                "Ln2q++O4obBjUDvv2U7ylmMAB/c/trSRSiOScCp9/xA4CqXeRlPX3OfvcIX29F5N\n" +
                "kYakCUQ0hETCOLDazh1g7xVJPF3y8oIXidy+NxF/dFp86xbsR0KHjJoG16lxFJYS\n" +
                "hXZQjAoUXLBHI4hTL9v/05+lKiDzCfDp+QdSZbPXKI8hlpwo1XPF\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfXMwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkyNFoXDTI3MDQwOTA4\n" +
                "MTkyNFowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQClOeKAqkmSJURy04JLMUTaa9qlWGlOrfqe\n" +
                "CwT/DamYWKxyHvFAuZrxgUKbrRPlCMsShXlMO9b/DygVOUlkV7410w+f4ylGOsz+\n" +
                "C8sMCo5ZOToHLHnbf064QzC9yww9DeJ/LXxrUtpgehX6VXcV1tg7iR+CSntoKWOL\n" +
                "WlrqTQZlv5jf69d4mOlQSHY7GvU5zdaVV30BNj6lxYZDkty2bh620/3t5u9GycKR\n" +
                "6rL6D3ryN36av5rE/Npy+TISToZJRuAQG3gSzP9OKwuwt6+cw8+RKevRdpRqfipo\n" +
                "2Y2DQsTV0zrn3T0qbiGX56rlUBhSnZWdZpGt9DkroNUkKZmvISgTAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTVfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBRo4JsRlvr+4kzrIodk0eO3GYo/XTAdBgNVHQ4EFgQU3O2xYLNS40G2\n" +
                "LksFVqA8H9PooxowDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQCJ\n" +
                "wGmxZJYa/c6GgnRHh24c6dma3aOIR5divrqPH+PxnJGG2baoJqFBnxUbwLdN7Ku7\n" +
                "ONRWceJJ7Zsw5en5vQipgj3IHP26qyaXyRLpym9i9pnn7OHma+/nLLpyjzAekXjn\n" +
                "oRG4UyfTVroHbRy6C1imkJ4AIs7wYCBNijTBmjJV5TyEZgK4f2n0bSDvRkxvkWgH\n" +
                "y514CnI3GNaEANoRcsVLBlemAS5sThoknjpusZ/YWUnOVsh3PMkpcJRipZsRAit9\n" +
                "F/YnEEYwEn5dHozB7ULy2HgKHuQODOK6A/MKD1Lut9JIN3IJT68jrjY30Za4m5/w\n" +
                "yKhDG/LEI82CB2ADwmbP\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPUnsupportedCriticalExtensionException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Unsupported CRITICAL OCSP extension: 1.2.3.4.5.7"
        }
    }

    "CERT_PATH_OCSP_16" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSEMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTI0WhcNMjkwNDA5MDgx\n" +
                "OTI0WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCorRA63/eT4qcWnU2LMHvCQZ8O9Eok\n" +
                "5VMxzQjzCiNC9JvZPI9L2Ps8dJqFUn6jR8Q2+ispBT5TJS4cTn7BpamhtMM9fCjD\n" +
                "hxUhyx6bDD5Hx0MBQ+GXIqdmPl4m0hSTYZ7Kud436x9v6JvUwGt0PW0amOZ/IKT7\n" +
                "8eq/EUGEK8zS0imBUvUsMmLrYiFl1TcqNjAzQr5LrOb9z8sz0enXNs+0VmlNz8iy\n" +
                "hZ7alGswT9NhSUh8z3Omox+rSVDHdgAqBUE5Hi7GM/9TnZ2A3XWn1qxCBTXhhX7y\n" +
                "kkHFdGogKVVESKc3CYFIQJltibYfW64yFGYWDGQy2Z3NveazkiB1ELaHAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTZfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFHCdZlmY\n" +
                "+PF8xkP9EZ0F6+ZVAhZCMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBsN7T+yvvGfbakh5iBFT57uKkAH49Qfj/T\n" +
                "/sh3KK1sH3XE4jbQ289j/VdFriSJLnJt6Vy+GKVXhdJutWQX4MF0DZIMd2YVJoQN\n" +
                "UNbIBqDKyPqSMagf7c1ezESRl9wQGnxJieoFFf61x/OWeT+PUnhAR3GjjNieMEXB\n" +
                "FZCM56zDHfEPGCqeIFNww4rsr1VJYlTAufllaPP6llNrJc5xD3uKFLKwL/IggJYU\n" +
                "OaoeP9cJK+8Pn7FDEgiZXOA6JLea95X2mAbt+UBXUUrrknAyf38IMuoj+qigioay\n" +
                "w9eXLU0rYFedXkST8apD0emRrllvL7PWqK4/n7NbP9jjPfYDbC2D\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDQjCCAiqgAwIBAgICfXQwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkyNFoXDTI3MDQwOTA4\n" +
                "MTkyNFowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuYiLwvtFJM0hQ1p5kyUNn+lQ6pd9htnu8\n" +
                "E7YstUFxySBXSjeSk09Xh1WcMm1WtPJuRUuwvRYAqkzV/yAQhianDrvmcJbYArR0\n" +
                "JW2frV+v9/+Q0wuWK7hHgF514hEsGHUj5Eg88jE5rKAO0A8S+fLRrUmgEsvdki4d\n" +
                "fLuL2AjnW3IRcGs2iZdGdSM3vz8SVtyw/Nxr96rZq859/5eiLXZRlx/Gw9eyBMS1\n" +
                "CNWrq8rwTPWAj+4ckVyKGr4i7nQaVTSyd6YTApXaB4nsTLuOkiWM0hCQujhJwLzn\n" +
                "PuqojgZx1i9Df7gj6OQU0zEyt611Q/+29I6Ga5ERATy1OoQquK3BAgMBAAGjgYMw\n" +
                "gYAwHwYDVR0jBBgwFoAUcJ1mWZj48XzGQ/0RnQXr5lUCFkIwHQYDVR0OBBYEFHxR\n" +
                "uV/hUB6RDytfx130mw0+a1HbMA4GA1UdDwEB/wQEAwIHgDAPBgNVHRMBAf8EBTAD\n" +
                "AQEAMB0GA1UdEQQWMBSCEmNlcnRwYXRoX3Rlc3RfaG9zdDANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAN8pZnzGjyqJh8oOKYiWJBNr65n/cgqBltKOJE3tlH/LzF2HXltVLIOx8\n" +
                "4bPY3jWgEdl/Nhc0cL+/LkNiGPIfOxmN2Z4QN1461hG2pwYSZ5MHcu4ovm7LV0tA\n" +
                "xV6Pji+SdG8WG1NHhaq3qk1g611OBkiHmXcaI6Ny7In1XYcVDjoFf6tlwchqcbmo\n" +
                "nHHUY+LUwLTbE1iHwKO3zU5hH/ucDjiVASqOWgREHPJtCSqiXyGU4x4YkoW2l907\n" +
                "tlEUaLEhI7HFhpQstOUcmrYYa/AhNQuR9m2DF1tKH46ulQ9b7QkZ6RnCi6k2Z7yv\n" +
                "LsL81NdoVZA7HK+I7zeGQYH+fXHocA==\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPMissingAiaExtensionException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Missing Authority Info Access extension"
        }
    }

    "CERT_PATH_OCSP_17" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSFMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxODU2WhcNMjkwNDA5MDgx\n" +
                "ODU2WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkob0REmYx2uByByHQ+eWo4dmaI3d9\n" +
                "7tBE5qbKZ0P4Qygzga3NZbcVJceLb/HrMT3y/rQ2KFccFrPfDiekx9OWJib5bg3q\n" +
                "cB2P96YfZCAC3yEU1bmPlWUHweW++fUaC3ZVhsHajH9fRfsCoNc7/cMjbozmW93P\n" +
                "wM2/jemCr+M94sqGdjULJMAUv+JjI7U3je3TWQ9SozO2Z1NaDlcwnVpSNApPdMO5\n" +
                "hXG5oTbnCQm60Y3SJ/HkAxDyUP93SAHqxluT7G6kLK98nbimhC8uIzNqqlD4belH\n" +
                "L0ipTCFCTGy5xuUTkmD78AcqTusnZVEl2MqQ5k8OwMQT/dCDxLrRV/gZAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTdfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFN7x4SCQ\n" +
                "91v0PLmSlewjybvn0wrtMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBVgrJU7+QyAMiJG8XMFRKE3MULSA0EmlUL\n" +
                "g+k1zY9br5SShPmNRV8puOuxGTNvqmYqmvu9XJvZUICpTmhXsBj0+PHxwkYSV275\n" +
                "W3ydMkehBn4i1wTHlZYscrmsUe01zpwXVU/F1Pfz2EYTvP3VOB4dDveA2bF9Ms3j\n" +
                "wSOzIGqkUmfGdSNYtQmKX5oj+fkVLSvkd74MsCNRivIoALxclutclQkLbbt9Gs2b\n" +
                "10TFKmKsYUzv5uwWX2+DF/qGXFU+f4HqLV3/yQbQ1qIcWLnyNL2N/c/ORW63pB1p\n" +
                "eApNXgGLKCvZqkf9BQvsmuBLDycMcwCHmotoE7oBsHdgaRkyyHxS\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfXUwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTg1NloXDTI3MDQwOTA4\n" +
                "MTg1NlowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCniF3rfKI1n5puD8muzcjlcKCmQ3UYWlqQ\n" +
                "rF0+J20ehGmZeTfOQ9/pEQFSG2PaYIUEX4Jgq1mmBFW7uduUbo0ZMNlP16QJJqmh\n" +
                "4lGlM1qnWkxxmjv6fjafu9+6b4mf+WNCUS5SSPUIlOd2YGdbUvj9jW4FuQPCYFN8\n" +
                "RUx/qwaOgnr333eow62VCaDi6rB1KE4l3b7KQm+9aoNiiz5Njmy43oDajceoPMtC\n" +
                "4ZsgsykKTQi7F0A0pw11oAUbExrEWZ8gpcgXm89yjEny9GERAWoVVjbDsmvRjqNb\n" +
                "WjkHspeE0wUOfHy2EaiAAcBi5I6L4DLWhBKaE8nmAaKz9JDrH4wlAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTdfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBTe8eEgkPdb9Dy5kpXsI8m759MK7TAdBgNVHQ4EFgQUCGwP1Ua6Ex49\n" +
                "f1NtmCu4Pt1bKVEwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQAf\n" +
                "WupLK2MP0m1wTsfDwUn4d+xXz5QIGha/3oeXBOCAZadeTuq5ByPPnafWvRo+/nGQ\n" +
                "w9ha/H9KcPZIzQDqh9xNx9W7+0sTen0K4lwuxMMvne2yfK5CGcqDb88ngNci8FPA\n" +
                "V6Hg1klyZvVi+GgeETOx0u5XCbEx+Beox/AvydsQJ1HxPU6F7wOrxJlec4/6UWYs\n" +
                "UgxZ4WdvUKy2sK6H23G91AjMuw9XPJwVGPYv8p4SQOYQeXcCmkbc8WKBdUHihQ8r\n" +
                "441jiZDcvz9wZDgUSvEg/tjP8wBieDPYVsx7DulrNVEsuWRcXP0xEiuOciaGlzgB\n" +
                "e3QO8fLPYUwO9T+pLIDI\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPResponderMismatchException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "OCSP responder ID does not match signing certificate"
        }
    }

    "CERT_PATH_OCSP_18" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSGMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTI1WhcNMjkwNDA5MDgx\n" +
                "OTI1WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCG0IUyTIY+qWGuE+6W1NUk7I1+BcRt\n" +
                "d09aoG2JPxI9utiy3TMeeQtNYyQLH9LJ2mi4u2RcV70r0jYMDBNeaym4xBipwG1p\n" +
                "PJsfxDIxFbgke7plazmAczx+YMIDKQ3vEbIacQctY7go239x8pMSoAOOMd9F/ryx\n" +
                "rkur8jHOyPxBpBxOB8FMfgFAkPGwKFR6SDxpPguMIqW6GYzFRBxfTRHXMktQxiY/\n" +
                "hFmeyAf7ejLAkxi1AMo12vIm/NGajCXYLmoN30J3Q13hwp70oXNt2K4M8HzXBcKh\n" +
                "WNcDXEDgygEcJehCBYh58w7AQB2TD0hd9IcaelqPiEOD+02lsq+TDY6VAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMThfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFCnJYGde\n" +
                "1UCbjH5dDZTie3+ltQn9MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQA2MwCuULvsgoqUQqOxBv48mxdHqlEBj/tD\n" +
                "/jUnjTlKUb2iRDLqjg6Mf+x2r4d/6RzQWlu65TUTrvkDMJ7anxfFZ1eSPNuHigAP\n" +
                "/KFx+ZJRGM/E7qCraz0JM5pqH8te/R+LtAZq2fao+46pOstqF5yCeLoB/WdjvVT7\n" +
                "0KxhEb9pqriiW8wcnIK+zucV5RohxXiUOEa5oUf+5aazyDSD/JbdqOMum6hBcRFR\n" +
                "YJ0aXQA+ZWvtNVQcWFwg9oRm06q83E489CkSuUw/Jc764oyx1qPhEkqoC1bWPpnk\n" +
                "+Jr6N1bgJvTArMbVOnR+QQyYkiNplHLNpYnaUN7xQJBru2DNX26j\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICgoowDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkyNVoXDTI3MDQwOTA4\n" +
                "MTkyNVowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCMhW+Lpn4pljyjv1wyCpTxrUu9SPowFmdb\n" +
                "R4Wt9OFv4SdqkXSjLVOFuO9S3+ln01hotElcSOlK2Lm0XarZNkiETX/7xYBbwjbD\n" +
                "0DokWadiiA4Ac9xwypdwNLIN6Rjimph157ACpcK4TT15HCNisEEWe1vKaUwVMaDX\n" +
                "MeJa/vNYvGZJRzdjTTf6b8mzOIs0w78SodD6sDHgvgBjI3zVy7hp7ak0VSnzcSVG\n" +
                "XBT7V68nyKGYy74mB8nwx/9iGLw3d737fC4cQp69qONmK6GF/qKfWC+pSTIbd2eg\n" +
                "VJ/b6UVulAnNop+kAmszunAjDvNqpeznRjtJ8IUN4vCed9VIah9nAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMThfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBQpyWBnXtVAm4x+XQ2U4nt/pbUJ/TAdBgNVHQ4EFgQUGtGiA/KethG3\n" +
                "VYwRCyHNRal1UekwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQAV\n" +
                "XMWvKtU5/vCU3kdXXC7piYAUd2iNR5kFn//pIw4cAvle6cMJmdrpYY8z5fnsbtMx\n" +
                "RfsH144xOayBj5FDZrokmC6d4RRUnT+jDekaNip27buxdUY6ZyyjS1PjRTRcghsS\n" +
                "iqZKp1MXXamTV8HlrxJkFDUQn/i24HJEPBZS19iNBRAPk+e5hIrzwwmzTPNhvB9R\n" +
                "APQQdCivPOZOB5wtcSS05/0hynVtRSoguZBMLxRs6Y9Pod4VoB7A3475zXLM0q25\n" +
                "eQsoUzOlu8hXY7Eo31KVX/czdi/tAfa28mVx5b+CPcCqC3SLoRD9k1ffQy/8neGy\n" +
                "wgG+llsdZGhml4oor5ts\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPCertRevokedException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Certificate is REVOKED"
        }
    }

    "CERT_PATH_OCSP_19" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSHMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxODU4WhcNMjkwNDA5MDgx\n" +
                "ODU4WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3Qvj5a4X+I5mqCBKS15cPV7ssBKW5\n" +
                "NV/qgm34GkWdt20Wz2fyb5TVoBm2YC2kfzX1IGgODTvUd9lQBk4wfFuNaESRHEtl\n" +
                "w1XoSuWVkRsGF53UDUHtxZBBSkgJ7+Vk4RQCG4CTqbBeeTRUKEPu1GY+/HkGkRny\n" +
                "U10wFOUK6Yo/a1uQTA7i8zu/S7qPdsmKPYWkUYJQpj4Sj5nxrKswkbOvMwdmmIrj\n" +
                "Ce+K3H/obiFlSpTcD97ZOGwWvzLu22lBqxOMLOmNpappyvbewi41zVLucQfm2POi\n" +
                "me/NfHGBGhurTfjkHSrejjSJ31Bfbbrf4jtgKDD22Ew2EOHIaCBO7mklAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTlfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFPw9x80p\n" +
                "bL4gpYKqdZiEdzx04itsMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBo03R9O5dqhhM25IiciUOCC83hBTXpY9ka\n" +
                "UMvUdiRu0UChHPc0jHSdWwvz/xPlZjdIaGeC3zsU0QvzlAZIvd4CA2hwMPeZ6ASL\n" +
                "nwtGSlFraAOabpbXQXeX7Gox4m5kJ9kHxkSzQbyLNnJoOcLx+fohkNSzrd48+qev\n" +
                "AhJ8HuKQQWjXu87VKgfCsh5ZdhB1DUvwbhK80Vu/JYEZ5YwOxFxikyXZLfHbpAOQ\n" +
                "EZo55fNMz6vXSLvhH27FSB9CD6KV2OJoOif6iqj3h5wwbEAHIrKCg71g8iITzlsr\n" +
                "5eLfkdvUVveRDcuVUPnKry/VlnlKRQH9rRqmlAG66U9IsRe6BHMJ\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfXcwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTg1OFoXDTI3MDQwOTA4\n" +
                "MTg1OFowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqfF4+papA9KY0ZPFMaMNuZUqXrtI7dZa/\n" +
                "Awj4hjBo9Yd/gg6PAJFjN/+bm30IAHJXDz7XDvSVf/rChYp668YZtvNNo47kUrRC\n" +
                "v+4gWpNxM+MB7i3QZkhaH7eiMN14Jdk1bBQK6h7HUqw1IdZFmxtFBRfFbGPZ5AZL\n" +
                "dxknnTIiC9N1ykxU1d4ZJDPSRxBzIPgEwuKj8iDAoVlfFYyT7J+GB1m4FUGuwq9i\n" +
                "4xCyEc2bXSAWSTKH8S2Y/KWWguEb7e8jEHckZuCmijhTzIog85M/exz6lL9+xtth\n" +
                "+Mzbfexl1NsR2fWcyRahJkjqm1yp9iFSzXF3TFRWBPQEp8C3lqA5AgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMTlfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBT8PcfNKWy+IKWCqnWYhHc8dOIrbDAdBgNVHQ4EFgQUGdxvkL87YEYS\n" +
                "laoHFZWiL3L2yfIwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQAS\n" +
                "+OddbhpQ6WX4uw23konVVk3/jvTzLyiTFf0Y+NAHqG2mQJ/YGkqqrTJuyQpxpVQB\n" +
                "xVXilz7vmppzLWF22TUDE48c+/Aph/t6uMUuki6RSdDeGdapmfCLwwhx5rIBCNwB\n" +
                "TX83KK6oq72GYd/Jfo6zXvwlZDgL1KzMxYIUzbBWWZnbvH0KebRH3JADbpV6m9R7\n" +
                "U81+T7NX15mKqOz374bFeet/7CzZGh3YR6oKxod5sm4Thfc02Y0xu+Fno3EnuoDc\n" +
                "WUFa7RVjgRNPptwC2+OKoMU0kReivTffL891oX1gsRz341+lCutzlcxhHwbrn9iP\n" +
                "ld7DOsoJQZd7PQFwx6G2\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPUnsupportedVersionException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Unsupported OCSP response version: 1"
        }
    }

    "CERT_PATH_OCSP_20" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKSIMA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTI2WhcNMjkwNDA5MDgx\n" +
                "OTI2WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyzpcdgMjVc6Z5u2nNbJRRia3SanxM\n" +
                "yB/XnOBbkCoy+Qs7ty4aDd4uNc0iwPAemR0lfatIbXIgrec52n8vGGD38Js4XFQI\n" +
                "E/P6YHT8tqk9/kKfFImTakrFJJKdz2RBkGl+0CymCgwtLnuEUDD+dfQZc+EGxqwR\n" +
                "u6rB9BqHZedHTqqwXDMko6lIaEg+/1tFRq+Wu2Ab/D83GvLFCOdON0zq6r96D2Cg\n" +
                "3Nely7AKE6abr+VgtLJ1dV4nbCvZ+yDNWEBekuuZDKYPdDOFk2be5ipr7Aj5rAbC\n" +
                "iCe9J6ei6CH7pVH+uNpmiJTkY9b99oeHl/OPzndZLEtzaU+Zolf6fcEnAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMjBfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFBdhn7HH\n" +
                "HrYLrDHQwXlz71T6+iR0MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAq/I/IrQCkrlKeMCemP5BmuMAoIvMcJDNv\n" +
                "KdyfTTBazE9KhvONu1uURnflsq3LIhBw6GRrt4vXr6KSK+TLMBe1J9oakO7Mpth6\n" +
                "2peihCfRnLOuPNu7xt+Z8hwUHSdWMBVcvJzRed5EEGH5D4zV8BDi48RlLJjAOyC9\n" +
                "3VWNtCa9pIdnr3JQRy8W+HYO8lsTl6Ik0PnR1QjVivUzDetq96zFGgOS9M0TcCen\n" +
                "2c+RIbmILoMPW3/SCDCvuZAJFbiaECvThkGPdCngm2jpL+EF8TJFaN/71zPO8bNu\n" +
                "zULIhC2Gr0klAgB5Rg4GJJ+LnikwzfdqTaLjO4XyEvbRzxt5Ln1K\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfXgwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkyNloXDTI3MDQwOTA4\n" +
                "MTkyNlowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBEyA/k7G6L6sAJOMJCjCowQU4j4LB0yHW\n" +
                "HEwTwKy4xVcPh9sYP+fkvCkhWOAKJ7lUNLZmLgNtSGqxX6HHz6nYMPlmpuTHWDGx\n" +
                "oorozyowFRpm1/E64B3owBRuOO6UwNXhoJIDVuk4MH88VWJ9YhsjYN70CAnuFCQf\n" +
                "BcUr7PGSrpA4sIO9NnHiYUIIWU1aE6kiqznD8y0aXG6Rdw7EjjKqmNwlyowFXTRy\n" +
                "KtsJdm8cOJUAUNZEg/te2RM3gxJ46Er7OcggNvDd82VKEGkzLTAxgoMUao7T1vYc\n" +
                "EbQcHhrruB+rTOIOXlzIkxlHDHdwtPhGxTcLTZeXDMY8GaK+gYkPAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMjBfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBQXYZ+xxx62C6wx0MF5c+9U+vokdDAdBgNVHQ4EFgQUKK4U6nVuxD2C\n" +
                "9q3Zf4V+CRjE30QwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQCf\n" +
                "5lNBN0+k8vqpYZlXhqAyt6mGe7Tk6LJuqeOF16BQ9OQu45vMmQ1of4pO7DwFeosW\n" +
                "Lpu0zNlYVRkCEB/PS7I9jIWNHteduCgCHzFnPgVyENa2OW3HzACxXnBqRdyXQ2kQ\n" +
                "b+fgeKInELHwBvIxFcaKdX76qqfBGd7GmNXS2BSwZ7HPOe1PoebDTEVTG2kUVnbb\n" +
                "L5vw5BZztXnQjOW+jA1sqnmc6CSqMvFGUW/lQRNo9mrWCYKGx9/rp+tFk83LyQQ8\n" +
                "O0ifzGtvqZKLqEvQ8TG7c3JV/eM02swajse2c+vyVKa2jMh6vgniirV72gGvwafl\n" +
                "qEh+cT3hOYdov1Hmd25r\n" +
                "-----END CERTIFICATE-----"

        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))


        shouldThrow<OCSPResponderMismatchException> {
            ocspRevocationValidator.validate(
                chain,
                context
            )
        }.also {
            it.message shouldBe "Subject of issuer cert and issuer of child certificate mismatch."
        }
    }
}