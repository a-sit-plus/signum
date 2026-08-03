package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val root = Certificate.decodeFromPem(
            "-----BEGIN CERTIFICATE-----\n" +
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
            "-----END CERTIFICATE-----"
)

// TODO: Add comprehensive path building tests using real certificates from public PKI test suites
val PkitsSubjectNamePathBuilderTests by matrixSuite {

    "Invalid Name Chaining EE Test1" {
        val intermediate = Certificate.decodeFromPem("-----BEGIN CERTIFICATE-----\nMIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\nMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\nQW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE\nBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT\nB0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37\nXfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa\nBGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47\nRuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn\nUGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+\nVmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9\nyrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ\nXahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC\nAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ\nKoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m\ntvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo\n3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu\nFMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s\n6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG\nQYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=\n-----END CERTIFICATE-----")
        val leaf = Certificate.decodeFromPem("-----BEGIN CERTIFICATE-----\nMIIDjjCCAnagAwIBAgIBCTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\nMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMR29vZCBD\nQSBSb290MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowYzELMAkGA1UE\nBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExMzAxBgNVBAMT\nKkludmFsaWQgTmFtZSBDaGFpbmluZyBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+nEW5gQmCvT4PQ4bfEwb8YmHX2\nbhQjlGRTHO894s1c8ntn8sOGipmZujpyWKEnuLYYXnrx/8d6EaQ5iHWc2STa5xO2\n/FYakp8YF7+wGIrvAKI2gXIaIFzFC6BBtZiDBb9esrLPA3tiu6u5F9WBsGWuA1TQ\njKqaTll9i5WvnXY8Fq4JbfHOeh9SCJKnyLtY/o6QqfJu4IvGIy3SVMUOpy35ZR6O\nHdy4JXBISnOe44NDd27PQNnkb7VlcvspL873wQSp5YJKW5tvoPMtCGegEssZIGGN\nlN9bNTzeXAB+BfwtYoqP0Ej769uC6863UgGeWztLxe5YlvyS7CXaMmNdyosCAwEA\nAaNrMGkwHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2lEHIUUfWvOskwHQYDVR0OBBYE\nFBrADjt6tfm3fhTgKkOCvTN+XnXkMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\nMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAHmYLicHjD0aYoBwgy4J\nfY9KHQVyP3enwjKFrzxt3lLh0+hvUeJG49oxt3lRPjU5d7GJYSzB9hmbECnD8hYf\n/NVRIa6UnLTK/blp3yc0fgYrZSFgzU77f6i51hxScIwprI/rNKUKjwYwPBQ6XZoS\nLb5nZkbFoSaPjorD7/rTBp1A0vPt9QNn8wBph59HSKyUnHm256Y5kv67Knkt5W11\ntazp3HAc2nsE21MClKg4S4IHQYCva6p3KhViH5Wntu0AaG6Cl3eVbMDe+rzu2i7a\nSsP+m1IhK/geXvUOHGkKQd0ESsNaHakpy5mQXpYbxxpem1NCcsbPPlipMa0AN5p/\nksU=\n-----END CERTIFICATE-----")

        val chain = listOf(leaf)
        val intermediatePool = listOf(intermediate)
        val builder = SubjectNamePathBuilder(intermediatePool = intermediatePool)

        val context = CertificateValidationContext(
            trustAnchors = setOf(TrustAnchor.Certificate(root))
        )

        val candidates = with(builder) { chain.buildCandidates(context) }
        candidates.size shouldBe 0
    }

    "Valid Name Chaining Whitespace Test4" {
        val intermediate = Certificate.decodeFromPem("-----BEGIN CERTIFICATE-----\nMIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\nMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\nQW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE\nBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT\nB0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37\nXfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa\nBGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47\nRuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn\nUGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+\nVmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9\nyrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ\nXahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC\nAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ\nKoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m\ntvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo\n3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu\nFMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s\n6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG\nQYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=\n-----END CERTIFICATE-----")
        val leaf = Certificate.decodeFromPem("-----BEGIN CERTIFICATE-----\nMIIDmDCCAoCgAwIBAgIBDDANBgkqhkiG9w0BAQsFADBGMQswCQYDVQQGEwJVUzEi\nMCAGA1UEChMZVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMSAgIDETMBEGA1UEAxMKICAg\nR29vZCBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGwxCzAJBgNV\nBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTwwOgYDVQQD\nEzNWYWxpZCBOYW1lIENoYWluaW5nIFdoaXRlc3BhY2UgRUUgQ2VydGlmaWNhdGUg\nVGVzdDQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4La/z52GYvBOP\nDFvAnfCjhivYpHlbMWtU7svc8tBER62tEOta4nC30i3dcKjgB4jKDM0F/u+OYl5Z\n4yFB30IiJm1OTj7IPf3ByvpExvPpHnVzsDHejQxAYSFIzrncOZbFmVbMy9cX7D4W\nhNQV4NAokTP6yocnUTxjyStNrQdvFvddslImXHlFUhLDSms8iW0DUbxkKoSajmBc\ntUMNb+fF8UXzCKZbrLX0Oe3Yb9DsjooJcbDWPosIx5f4JuoqBPZlAYzbfLY6n2mi\nzuITEX8Y92Frb8IHPV5BiGB6BH6zacuSPpL2wraRdgZ+RDp7LhWLEgeoEgVpKPJa\n9NkL8frjAgMBAAGjazBpMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJ\nMB0GA1UdDgQWBBSbK6wW/RUIeRut/gCL5ZdIwM6pZjAOBgNVHQ8BAf8EBAMCBPAw\nFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQCMYzO9\n+8BMUK03i/AJRqCMqbqswHkkb9HeVjXHy+NzN7WK766jlSW/uTQ0GQSVdnU7Fsz6\nUH5gLW3U0xngEYRP29iXNVKvcowLt9QDnHFOSyIQDPby499+YulERS5kAOhjm7pt\nYq75dLt/tNpEueSYzI9oUQzwIGpkyaVVlfmO/FJZdhpJ9MCZjzWoUhuLxXIQm+mD\nUAme2M514vtqwa8RG9xUQdO/CnXZKhAKNp+VK2zn5qt9FynWL5k1kMmxUkuqLapu\nduPbakDGRpP8vsj9QNWSmE2h0ZIZQ620VZ9121qhv9hvngL+RJcryL3aAbgQOmk3\n3eJOprz8zBsDGy4q\n-----END CERTIFICATE-----")

        val chain = listOf(leaf)
        val intermediatePool = listOf(intermediate)
        val builder = SubjectNamePathBuilder(intermediatePool = intermediatePool)

        val context = CertificateValidationContext(
            trustAnchors = setOf(TrustAnchor.Certificate(root))
        )

        val candidates = with(builder) { chain.buildCandidates(context) }
        candidates.size shouldBe 1
    }
}