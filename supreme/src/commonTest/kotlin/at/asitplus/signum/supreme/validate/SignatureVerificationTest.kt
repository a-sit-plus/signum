package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

/*
* PKITS 4.1 Signature Verification
* */
open class SignatureVerificationTest : FreeSpec({
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

    "Valid Signatures Test1" {
        val goodCACert = "-----BEGIN CERTIFICATE-----\n" +
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

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDeTCCAmGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMFMxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMSMwIQYDVQQDExpWYWxp\n" +
                "ZCBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
                "AQoCggEBANncdxgQEBhgQfvneBAP+IR3cO8tblU7EaaZUj9t9L2hl/o2Hm5EQhHI\n" +
                "U/51hpteNxKIon3ZcQjUSTVxzkbPW9BZjmUf60I9yg7cTJDYVGnPXjiyIGDdg1Eu\n" +
                "39vVWziRWi3PmjO0b5aQ5XYUYkNphBDPVEH5Neqe1FqXnV4QWb3g5MNZidfe8nmw\n" +
                "h2sCwFmhKgCCFW9rEREAUzR0PfThzFZiouRl6COxgx1YUwiyMy2WvuV9M54QWidz\n" +
                "U91dmOJLEVNYkY/qchHsu5TyDQ9QrfIWtRoAJDHlFb0XBpCqJLGs3QxSHvCLaqu4\n" +
                "9+3fY7TOlGi/XpbQRJbx+PR6Ogp5FVMCAwEAAaNrMGkwHwYDVR0jBBgwFoAUWAGE\n" +
                "JBu8K1KUSj2lEHIUUfWvOskwHQYDVR0OBBYEFKg8CZ1n9thHuqLQ/BhyVohAbZWV\n" +
                "MA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZI\n" +
                "hvcNAQELBQADggEBAB5a2Q+vYqW5Ury87AxhiBMBqgoPDUejnqmyFxv4o9ks0o04\n" +
                "vjuyz9QxiM/OafSOx7lwBVHABofGlbT2avoxni3EF7Pt5XoZYRhujNHkDtqbbWyN\n" +
                "BpDuLNF5WNiEzZtB0xji/pHGXwAnFGV7Evovvai/NI4tzxdMWFswDy5pZkUmJiGY\n" +
                "0/OQrimHWk7Gvegofg+glOb/XLVcT92KYVkOBdL/xWnA04lK0cLlyPTICMP9KiNP\n" +
                "hABcLEQtg4rCPSLHPGDyinjjG0Zl2pmP+GPB1HqgcKZ6pxCbnax/vhTwRCOHWKwQ\n" +
                "FejzoL8eJcs2qwJpWq7/wG6wQ54Inhk8pzBujcI=\n" +
                "-----END CERTIFICATE-----"
        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Invalid CA Signature Test2" {
        val badSignedCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgjCCAmqgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFjAUBgNVBAMT\n" +
                "DUJhZCBTaWduZWQgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDf\n" +
                "77zrq/d3vnq9i8r8Trn+BmzL4FkkTxewQRXNUnk6QnZ3Zi929sKAyv6cHCJK0r3p\n" +
                "JQj89gjkcHFt4Wsqzo9cRS/39ynAiCBoPqdOdCiy6J1AhKjMAVjrx0U597QUMKXj\n" +
                "jQvxpsLptqnn6kEX0VQzHqrChCbYogCHGVzyOEM8EA4KK8byAf2ZwUE34FqcSYjb\n" +
                "XtX2Kl+NsNGEBMTiqNEE82w+HmuRM5XYxG9+3EnCuT5O5b4WWqzsvYHAXEzgu+K0\n" +
                "ghe4Wail7rFP1Ho046GZCwUzi+U518bek8liQ9qiqS1L6oVa8dnQf7QDImDBIb5F\n" +
                "+2IJmU/NPAJwTNAhK3mBAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWu\n" +
                "vnW2ZafZXahmMB0GA1UdDgQWBBR73RA7SuDI3USFTog8WovNmSKTrzAOBgNVHQ8B\n" +
                "Af8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMB\n" +
                "Af8wDQYJKoZIhvcNAQELBQADggEBAWS/T/8EU0O0tLjvTs5hWudZV+co6/NMpRBk\n" +
                "gUjCI8VuNjpi/bmhLuNioJ3tCgLWlZ4Lhd9fLyOvktEo5HtJ0HNedz1Nq6+L4S+u\n" +
                "h8yYAIXSawnnyZLof8p67U4Z0hz7typr+a9FLpbkvOi6KUykbEgNOwES0+2PZLlf\n" +
                "0O3/I4JLkA7w0JXQi6CyOgVlRxF6fxw4O3Z/C+u560TndrUaISdyugt9a00gTmZc\n" +
                "9cQpAfZUn6WS0xp4D+xQ1h1l8BU0nXR32uODwxTh4PHh6sjZhY4pWrwbRgBjKkzI\n" +
                "iqEDzQlzqYwtPjIntlbAkwC4KM1pFaMwZU+WJ79rrPJGMGWFF3Y=\n" +
                "-----END CERTIFICATE-----\n"
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDfzCCAmegAwIBAgIBATANBgkqhkiG9w0BAQsFADBGMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEWMBQGA1UEAxMNQmFkIFNp\n" +
                "Z25lZCBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMFMxCzAJBgNV\n" +
                "BAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMSMwIQYDVQQD\n" +
                "ExpJbnZhbGlkIENBIFNpZ25hdHVyZSBUZXN0MjCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
                "ggEPADCCAQoCggEBAJpto6V//mi4jC6Q4e/y1J79mi//TInYf0KaP3Aw5rsaMhC8\n" +
                "IJbEAdkIhfj6Skvg6uPj6gJB0zsmN9Tf8NVArEfcRwjAq7IvvDtVrDz6I5Ie0bFD\n" +
                "8MGkcdP0otJIpbTTHAcefxoqQQeTCt39X9viZokrLeBHWnB4L6zE4d05f/7Wh8ca\n" +
                "KlDiKjRQl8aIqj8wPsu4MlVC4jnSYTQ6wEd6cA3gJRygcUWkaLaVleaV+PYyUqD7\n" +
                "8X7p3+i16q1DzgtL9yXUP1b0rt48UWqfGBiIkTNUB0zN9heA7GyI/ilo1Ga8THpN\n" +
                "pha2SLqNB1rMWl3T9fRTsu0HGKRHZobhzGi7zJsCAwEAAaNrMGkwHwYDVR0jBBgw\n" +
                "FoAUe90QO0rgyN1EhU6IPFqLzZkik68wHQYDVR0OBBYEFK0h9T1WA6JYJDOopjeq\n" +
                "QZiYko4FMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEw\n" +
                "DQYJKoZIhvcNAQELBQADggEBAJKcaDXNDhjePhSydqe+QrUBUS0YNqamRezwkiQ/\n" +
                "NoKO8CMTNvta/bbq/tIYarPtac6n4d0rTuHURuCSC1l6VsruAWsNgn6Ja+G3nqeV\n" +
                "MP8WM5XYIToIPHy8OMzCXfu04IV2dAuaX4igWL3hn0PXrh7JnrTwfnK5ytSbzxbh\n" +
                "IWcFLpSqxL0XzEAfJz24325SbAyXqvwx+McF5UU34JHgEUQcvTUTXjr2Xp1i5moV\n" +
                "68a0CjqYABdZ2pDpHAWoFzvVrcv7o93Y+/DbR+5dVpuN2184q7cJcoez/c7aSp8W\n" +
                "A7R6Ggi+lJEic2RkktRRZTjh0oMM0ndj5c9Ya7CGfEN3gEY=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(badSignedCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldThrow<CertificateChainValidatorException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Untrusted root certificate."
        }
    }
})