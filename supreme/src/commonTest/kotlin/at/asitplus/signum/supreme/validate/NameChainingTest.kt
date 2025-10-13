package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

/*
* PKITS 4.3 Verifying Name Chaining
* */
open class NameChainingTest : FreeSpec({

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
            "-----END CERTIFICATE-----"

    val UIDCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDgDCCAmigAwIBAgICA+kwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCVVMx\n" +
            "HzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFTATBgNVBAMTDFRydXN0\n" +
            "IEFuY2hvcjAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMD8xCzAJBgNV\n" +
            "BAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMQ8wDQYDVQQD\n" +
            "EwZVSUQgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeFABwDBUn\n" +
            "ApJRGeo/+64E11KZ3rpoF+VJIX9apBq3DmF5GxhYb5PiFTkOPLN34PwLf3qLez93\n" +
            "SSgZv/lXeQhWnudJlYLTwyHleDYo6uzFzG97ud10DKLEL4qz6tsNmgOFN7DUsARW\n" +
            "cniQeA+PlB7FOAq+Np3AU3thtysN9pj/7kfthiHSpnaolauqdQFug2QC/Tsuqlpb\n" +
            "wdZmC+0jcjz6F7FPOSo/dkTb1gy04sjoA6QRuCAskjlkQvSuviU48CYZwlXJg87m\n" +
            "R6t5yDk1kv1NSUcL0g7PNC/yIMZiNKzkP+hVOYc/EK8dJv2u8rmp74xCW7Zq6lhe\n" +
            "jgZF27pmsTuLAgMBAAGCAgUgo3wwejAfBgNVHSMEGDAWgBTkfV/RXJWGCCwFrr51\n" +
            "tmWn2V2oZjAdBgNVHQ4EFgQUED/FBDDx2EM2hXlcjI2Lne4vHKkwDgYDVR0PAQH/\n" +
            "BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQALOuCe7LwozytIfL3W2cNZdLVrhfOXpE/spkte\n" +
            "1wi3VLrPYFYX/WMaoL++FBP2Ct3vMRaAmBHeAScN+FYPXP5Nc4DUiDlDXIC7oHJa\n" +
            "BFlZq50K9sUIfDUiH2acsdrNqwh6QRO5+tdah+kNRmSnq1x+b/gSVkruCyo/hgLe\n" +
            "XuvjLlB9CHf7FcD2TjT6kVHwTztZVOyC3PD0itzmla8BiY+Bx27Mmhk9ivQLeM/l\n" +
            "ZXScBDdjrKanYIqmcvdrHGVRjBzpMQE/Vq7wwb9pDsm0nUiaHcfJQxrzNOlIsov6\n" +
            "jtBJCP2luvGQia/7gwP8r6Ft2SsgMqH59wBxSipXP3qpz6sS\n" +
            "-----END CERTIFICATE-----"

    "Invalid Name Chaining EE Test1" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjjCCAnagAwIBAgIBCTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMR29vZCBD\n" +
                "QSBSb290MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowYzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExMzAxBgNVBAMT\n" +
                "KkludmFsaWQgTmFtZSBDaGFpbmluZyBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+nEW5gQmCvT4PQ4bfEwb8YmHX2\n" +
                "bhQjlGRTHO894s1c8ntn8sOGipmZujpyWKEnuLYYXnrx/8d6EaQ5iHWc2STa5xO2\n" +
                "/FYakp8YF7+wGIrvAKI2gXIaIFzFC6BBtZiDBb9esrLPA3tiu6u5F9WBsGWuA1TQ\n" +
                "jKqaTll9i5WvnXY8Fq4JbfHOeh9SCJKnyLtY/o6QqfJu4IvGIy3SVMUOpy35ZR6O\n" +
                "Hdy4JXBISnOe44NDd27PQNnkb7VlcvspL873wQSp5YJKW5tvoPMtCGegEssZIGGN\n" +
                "lN9bNTzeXAB+BfwtYoqP0Ej769uC6863UgGeWztLxe5YlvyS7CXaMmNdyosCAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2lEHIUUfWvOskwHQYDVR0OBBYE\n" +
                "FBrADjt6tfm3fhTgKkOCvTN+XnXkMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAHmYLicHjD0aYoBwgy4J\n" +
                "fY9KHQVyP3enwjKFrzxt3lLh0+hvUeJG49oxt3lRPjU5d7GJYSzB9hmbECnD8hYf\n" +
                "/NVRIa6UnLTK/blp3yc0fgYrZSFgzU77f6i51hxScIwprI/rNKUKjwYwPBQ6XZoS\n" +
                "Lb5nZkbFoSaPjorD7/rTBp1A0vPt9QNn8wBph59HSKyUnHm256Y5kv67Knkt5W11\n" +
                "tazp3HAc2nsE21MClKg4S4IHQYCva6p3KhViH5Wntu0AaG6Cl3eVbMDe+rzu2i7a\n" +
                "SsP+m1IhK/geXvUOHGkKQd0ESsNaHakpy5mQXpYbxxpem1NCcsbPPlipMa0AN5p/\n" +
                "ksU=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is ChainValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Subject of issuer cert and issuer of child certificate mismatch."
    }

    "Invalid Name Chaining Order Test2" {
        val nameOrderingCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIID0DCCArigAwIBAgIBBjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowgZMxCzAJBgNV\n" +
                "BAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMSMwIQYDVQQL\n" +
                "ExpPcmdhbml6YXRpb25hbCBVbml0IE5hbWUgMTEjMCEGA1UECxMaT3JnYW5pemF0\n" +
                "aW9uYWwgVW5pdCBOYW1lIDIxGTAXBgNVBAMTEE5hbWUgT3JkZXJpbmcgQ0EwggEi\n" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4Izk2uos/TlxMQIzTb0CugRjW\n" +
                "JZgTFHdIYxEN2K6eCpfTkU3yFaIIsqC84Jwc6sCT/uroouCtnBsDvoMw9ExsfX/0\n" +
                "wBKiXYZ0WmpD+cqNCmXJObrxsw3qs7fb55J9b+4sKMyBPea4hwOwpSpdnk/d9oY/\n" +
                "QqBac09/+bqQZi4gSM2MdNweomR8fzh8B1IgNwuObNH30EuuNpjjQfwdfPt53HDH\n" +
                "DlHAVDQgT3/2wrj/kWCXYeairC/r4IZFmCGPfWpwdFBy3SXV14yqG3rzAnOYoTvQ\n" +
                "qHIhOyj450InVnCJc3f2tP157JEejY3KxxtFT7JCb232thWZz0FduNKKx1IrAgMB\n" +
                "AAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQW\n" +
                "BBS/SouBm02MFDGMW+nM3S/oeRJRUDAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAw\n" +
                "DjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBAB1RfNIX2NAP+HC88I5JhXw8wDo9r7T051XcB+KVhbUfK7sKE9WXOq8hxsyQ\n" +
                "b6XaSwDMIlbxWNAeSl/8O7UGQ36IWepI047Y6wCLMGsOINtB5FGzPsg27mgS8txc\n" +
                "80Y8yyxNrGrztJJOPEjyw0fyfW56Vyjee2z96/5ETtJJMFkr1JnbITqdrXL1+cxJ\n" +
                "TH9KgJVXFNjr2vAzB4aV0lHcd1JRpfTCB7nRt+ALRqjfyUJze5NI8TN7DseNgGbx\n" +
                "UBD42AlUMC6aHyTWNytAsUabonJefRatkLzY6BpJ0Ewe8d2ztqIhkYGezCb+IXJL\n" +
                "m6bBRwtJ5KXTL3kz3toqdTJedcg=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID4zCCAsugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBkzELMAkGA1UEBhMCVVMx\n" +
                "HzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIzAhBgNVBAsTGk9yZ2Fu\n" +
                "aXphdGlvbmFsIFVuaXQgTmFtZSAyMSMwIQYDVQQLExpPcmdhbml6YXRpb25hbCBV\n" +
                "bml0IE5hbWUgMTEZMBcGA1UEAxMQTmFtZSBPcmRlcmluZyBDQTAeFw0xMDAxMDEw\n" +
                "ODMwMDBaFw0zMDEyMzEwODMwMDBaMGkxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZU\n" +
                "ZXN0IENlcnRpZmljYXRlcyAyMDExMTkwNwYDVQQDEzBJbnZhbGlkIE5hbWUgQ2hh\n" +
                "aW5pbmcgT3JkZXIgRUUgQ2VydGlmaWNhdGUgVGVzdDIwggEiMA0GCSqGSIb3DQEB\n" +
                "AQUAA4IBDwAwggEKAoIBAQCmGHtkF4itTUq3AQnzZatlEBh9xeYcGGHKW4YG71VW\n" +
                "tuN7bK7l/LNJ2rANrU4d3FvjcjS/uz1mInuC8Jmc83z4O6E07zDERh3vJMuMYZRM\n" +
                "/3Gq/b5MfGc2SSPiE0x3I8K7IVOjwa2GtYAKm7W3nEJ80//fkdRbzu9WYXLpKGfx\n" +
                "ffEZq4j8kBwmNGYLO2eyOmIKLeY/UdnzN+IV/wy9u4CvNQEoagLCXsaAsLJZWPeO\n" +
                "e+92n90GVdAdKB/Ml9PMTBfDh0R1jrmOFAEOcJfIYGpfj0tFIsAZ1AdcDNPXSx4s\n" +
                "A0cLfSG0xuJu6iBxHHIsCRW2Q2cK8yo2aIq7FNNE8bvPAgMBAAGjazBpMB8GA1Ud\n" +
                "IwQYMBaAFL9Ki4GbTYwUMYxb6czdL+h5ElFQMB0GA1UdDgQWBBRXIRom3xYohMEv\n" +
                "pN0iRtvORdgoWDAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMC\n" +
                "ATABMA0GCSqGSIb3DQEBCwUAA4IBAQAynecH6qf01AWM0adG9SZ3BQ5N/oBfcu7e\n" +
                "WjwU0dPuMZP5O3+Ak0x7lt9F4QRwmcoyHsB7AZgGMNu5xWE3dpebr4mF09RP0+pa\n" +
                "T0lli8Vi5QMUCaqYkbXOfchl/A9k2py5H5xrZ0OJZrZonmAGZTMmSuAhY1xu6scW\n" +
                "gs6X2CSnU8siNg9Zcd7jqbfHUWSLvz4k9N7UzTqT7Pzwof1vaTPqcggDGUC/jQV3\n" +
                "v6BgnIcxxHjRL4VSg4Z/fMh4hwXQlEFZGHoyBzzYNhYPnpgpxU/64cVHbOLNC6X0\n" +
                "sUVsT9JfCt/kFAPOoWnBOifSzjeqVXmteVsb/9SP4wF/f4gBmJjg\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameOrderingCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is ChainValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Subject of issuer cert and issuer of child certificate mismatch."
    }

    "Valid Name Chaining Whitespace Test3" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlzCCAn+gAwIBAgIBCzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEg\n" +
                "MB4GA1UEChMXVGVzdCAgQ2VydGlmaWNhdGVzIDIwMTExFDASBgNVBAMTC0dvb2Qg\n" +
                "ICAgIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowbDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExPDA6BgNVBAMT\n" +
                "M1ZhbGlkIE5hbWUgQ2hhaW5pbmcgV2hpdGVzcGFjZSBFRSBDZXJ0aWZpY2F0ZSBU\n" +
                "ZXN0MzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALHDyEmorSlP274u\n" +
                "/18BUHzKkc9SIwgCP7PBHTOfjf6Zy5H5WVZ0iPjotyQpm8nhiZLodmJ7I14LyQaV\n" +
                "gCQaZJR3gw5dKMYHotPXQcI4jptWTiiG+aNT7bZREbg5BA7jTswTLokWbcQHBSx6\n" +
                "iN6QfHS1LJP0ah4ccVVpi3sqDvfzhzWsU9s/S2pFUOHM6/iHc6H9Zy/CxceTHrt9\n" +
                "jw5A3KHRZ9ihMGuwZXZfZn7HHtDuVMUb23QRhBVoPo+QzCCGXb3Kxr1/qM1EiFgW\n" +
                "mkieRIPGygUkFoGyH+ELQNclyI1bb9jsW4g+vr6PTYgEJofktbQB3WwCRH7ADIW6\n" +
                "6fpSr/UCAwEAAaNrMGkwHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2lEHIUUfWvOskw\n" +
                "HQYDVR0OBBYEFM+4igHs3RwMuk/hDgGZXsfaFTxTMA4GA1UdDwEB/wQEAwIE8DAX\n" +
                "BgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAD5C0FF8\n" +
                "5YCkCu/hOuIAlLhMSkjdlBKlpnFriNjiKtNNPm+lEXUCnN9Iug/QrqevX1wTN7zx\n" +
                "glDipUTax7bo3/z4eT/eURz5shg4swHdnDofLxRDJybSEG0hEDUgu+lvww13FHFQ\n" +
                "6ZgGvgC4O5wPE1UVCQmM2EcVkcdn6sMLozzH+sg40gj/VALvh2H6VhobkV7dzI82\n" +
                "cGPZhPDNjO/w4MjGTfhQjPvMGVuLjazBZxNCyfZeYDjygmIDSDLmFAdum34Vk8OL\n" +
                "/lGLKLp31rM7EBYhkpu48PhPy8iUXAvR+qPlcKfbQ+k/D8rbzDE3tX/Iw/6LdhU5\n" +
                "3xt3vd6uvytI5dY=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid Name Chaining Whitespace Test4" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmDCCAoCgAwIBAgIBDDANBgkqhkiG9w0BAQsFADBGMQswCQYDVQQGEwJVUzEi\n" +
                "MCAGA1UEChMZVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMSAgIDETMBEGA1UEAxMKICAg\n" +
                "R29vZCBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGwxCzAJBgNV\n" +
                "BAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTwwOgYDVQQD\n" +
                "EzNWYWxpZCBOYW1lIENoYWluaW5nIFdoaXRlc3BhY2UgRUUgQ2VydGlmaWNhdGUg\n" +
                "VGVzdDQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4La/z52GYvBOP\n" +
                "DFvAnfCjhivYpHlbMWtU7svc8tBER62tEOta4nC30i3dcKjgB4jKDM0F/u+OYl5Z\n" +
                "4yFB30IiJm1OTj7IPf3ByvpExvPpHnVzsDHejQxAYSFIzrncOZbFmVbMy9cX7D4W\n" +
                "hNQV4NAokTP6yocnUTxjyStNrQdvFvddslImXHlFUhLDSms8iW0DUbxkKoSajmBc\n" +
                "tUMNb+fF8UXzCKZbrLX0Oe3Yb9DsjooJcbDWPosIx5f4JuoqBPZlAYzbfLY6n2mi\n" +
                "zuITEX8Y92Frb8IHPV5BiGB6BH6zacuSPpL2wraRdgZ+RDp7LhWLEgeoEgVpKPJa\n" +
                "9NkL8frjAgMBAAGjazBpMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJ\n" +
                "MB0GA1UdDgQWBBSbK6wW/RUIeRut/gCL5ZdIwM6pZjAOBgNVHQ8BAf8EBAMCBPAw\n" +
                "FwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQCMYzO9\n" +
                "+8BMUK03i/AJRqCMqbqswHkkb9HeVjXHy+NzN7WK766jlSW/uTQ0GQSVdnU7Fsz6\n" +
                "UH5gLW3U0xngEYRP29iXNVKvcowLt9QDnHFOSyIQDPby499+YulERS5kAOhjm7pt\n" +
                "Yq75dLt/tNpEueSYzI9oUQzwIGpkyaVVlfmO/FJZdhpJ9MCZjzWoUhuLxXIQm+mD\n" +
                "UAme2M514vtqwa8RG9xUQdO/CnXZKhAKNp+VK2zn5qt9FynWL5k1kMmxUkuqLapu\n" +
                "duPbakDGRpP8vsj9QNWSmE2h0ZIZQ620VZ9121qhv9hvngL+RJcryL3aAbgQOmk3\n" +
                "3eJOprz8zBsDGy4q\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid Name Chaining Capitalization Test5" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDljCCAn6gAwIBAgIBDTANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR09PRCBD\n" +
                "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMHAxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMUAwPgYDVQQDEzdWYWxp\n" +
                "ZCBOYW1lIENoYWluaW5nIENhcGl0YWxpemF0aW9uIEVFIENlcnRpZmljYXRlIFRl\n" +
                "c3Q1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7uBBbS4stI16Jp4v\n" +
                "WGJ51twPti1iJLp+mNzQjyNaE/xC+J3w438fQvsKPEJBwl9iuTtIO8ijAGRJiCUA\n" +
                "nnc7+PeJ7UvYBxE1tcggXXrE7pTJsw893bE6JHy6SxH+/yt/yRfwo+YqbZvtD+6U\n" +
                "4bCsj/83FQvhWoLdh0ePfU3GiK0wkM13aD+pBNy/aMZHIOm7JjOuv4a2hbQtYWHo\n" +
                "oYRYkhXfykCr37V3zwCbPsmGyVJ0MLtwLs/Q3Cqxzlp2uIoeFQR4e2H+ISfQg+Lp\n" +
                "1eIqJCd2E3VJ8oKcIu2oW4soNL9mPNjKZdlwC3VLtRITcvfPH/otHuS2wcAdU+88\n" +
                "DRMo5wIDAQABo2swaTAfBgNVHSMEGDAWgBRYAYQkG7wrUpRKPaUQchRR9a86yTAd\n" +
                "BgNVHQ4EFgQUeN6aGkOrZ3hSrA3gtRojk+AnY8IwDgYDVR0PAQH/BAQDAgTwMBcG\n" +
                "A1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG9w0BAQsFAAOCAQEAbqlb8g8M\n" +
                "w5TaH8PXafNxxswC41xFgxZWx4vdQEytNeeAdFABrQf79V/CxoT+KuXr17wTstpT\n" +
                "XqEF5zjsahruaSONLcUy1JetjUNW/Z7b6/p4s3NffYhf0TMqqLLatI63CCImH8Ap\n" +
                "8ceCFU3m+fyIyTdIEHgsnQX67zZ1mpoFjlrTutSYXUHtfhsK9h7LCprkBOwjbjfd\n" +
                "t2nf6nPx1H05oFKrFGpu2gAHHserXavCToQVsprK8jQ6r/8xHInJS76KK3fMT4Is\n" +
                "iA6EiRrqGTWkPjh2hd6WaFz/zRhuLm9ODRuz3bgN9rcdxq8jYkDg8Fq6eqhnVLJe\n" +
                "nwhTghrNhZqV4w==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid Name Chaining UIDs Test6" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgTCCAmmgAwIBAgIBATANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEPMA0GA1UEAxMGVUlEIENB\n" +
                "MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowWDELMAkGA1UEBhMCVVMx\n" +
                "HzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExKDAmBgNVBAMTH1ZhbGlk\n" +
                "IFVJRHMgRUUgQ2VydGlmaWNhdGUgVGVzdDYwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQC+CDXTTtVJkN0JuysaGMhtKLPv9bAL5wjPaio74JOJd/yT6Ht6\n" +
                "Wakzti6sGWJ+ZXZV/b06A0pjX42Ni28NhdQWVYdoePNde5WTbowdR2TOnxEAGJg0\n" +
                "ztClAEBDgAI6xSk47UJ0Dw0Rfs0hJcbLNQnqAHU1UllAX9XanFDrAVMzucVxYIiA\n" +
                "DF2dYc8k9qeWYp0iASwG8uNhOjV4yZK2qnP+Zbgvi7rfs9hRGFq41TcWmfgiEaPg\n" +
                "olDsycWP9+3xN0VeUQWSI+a+m/WqXfn1YlID2fDdBfTAluGZo0XgLDCaFEBTykbz\n" +
                "txF492qwzSjSDTRTFDOXeFtFrG7D7iw01GmFAgMBAAGBAgUgo2swaTAfBgNVHSME\n" +
                "GDAWgBQQP8UEMPHYQzaFeVyMjYud7i8cqTAdBgNVHQ4EFgQUtSL+I/d8UPhnT9HV\n" +
                "xez6eEtAmW0wDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEw\n" +
                "ATANBgkqhkiG9w0BAQsFAAOCAQEAVZmul1o1onioRq7Mh7wUzGcIsXfNPryARrfO\n" +
                "1+dn/QwbrfraBtW5LlUHgaqn0etd/7oy0YslTJ0eR0NvxyrJzTS+qENkN2DVlrUo\n" +
                "qcwE/P+9iA0eL3oaZROmf5zqOJ6dw0DHYHiEZH6u3rAd6fG1X0gQysvaDIlxMcCt\n" +
                "d6BaWAaWxn9GR/9Jwi/imjiVwgzZ5xlll2KuDBt5pv7Gl3o39KIGB/kJ4amgBA6l\n" +
                "ucxz6BnG7Wp5NgTRQpGnSptptIDinQy+0deTYoi7+iCttzXf9mrETOcTJNOZA0PN\n" +
                "86Y3oRXxtGlORZg9ikd6FpYqtYVw91S+v/r/yfYm10GHltaHbw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(UIDCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid RFC3280 Mandatory Attribute Types Test7" {
        val RFC3280MandatoryAttributeTypesCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIID0DCCArigAwIBAgIBYDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowgZMxCzAJBgNV\n" +
                "BAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRMwEQYKCZIm\n" +
                "iZPyLGQBGRYDZ292MSAwHgYKCZImiZPyLGQBGRYQdGVzdGNlcnRpZmljYXRlczER\n" +
                "MA8GA1UECBMITWFyeWxhbmQxDDAKBgNVBAUTAzM0NTELMAkGA1UELhMCQ0EwggEi\n" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDUNDElMAVhx/zv4YAsDhenHhRX\n" +
                "LtmaEBOCTKqCQF+rRfQuf9huc18yfKyylxeh/InZ2lRIsWDl7CSEHmE+mlHNt0xw\n" +
                "/oei9oPMSrR20+ZN+HqaJ5s4Ds3FNnIjmpgRlOPWokzqqCJ9Gtyu8yKL/cFhbiXS\n" +
                "YaADGz/ed1FqeiWuvfDKyaxPtG3bYa0Jq5iMuadfBQ3rdwFyPLaM3q6rNkDMrFtE\n" +
                "Whp34TooxaatF72fQKphvamcnf0QNhCpTQGTjxrdKtGOwI/zsuvSHmm2IsfP5uqT\n" +
                "DimedyldMhnqVomyNDuxfIUzR8y2Da6/UyCEEU7MN7LEAXaRD2zhLzF+SQINAgMB\n" +
                "AAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQW\n" +
                "BBTwURhi785Bx7ewZ3RrArwyCjOZ6zAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAw\n" +
                "DjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBACdlWQg/dlqwHgvP2lBoyEnv/xsOOACG7wzdNrK/CZzYL7vQ3tWrdVaPIEh7\n" +
                "B4nDconwjPuI61JiZv6kS3BsI50jVq0uIEYcYBPVTZIv334xnqZDyFa/Y65dUdhU\n" +
                "1Q0wKBxFNNlVo2dJDhlEjHAtUlvTDGVkCTk8sz4qsrAmu4KXC2ypEi6n33EuxF5+\n" +
                "D9+leUviMx88AEP7/8KwHTUtsHLqvzxCk3l2gt4oY+EuY7+hKGdvvkVev7LtX2My\n" +
                "5UuWkQ6jroQjHZIplTyOUdM5ZfbjMhaUQjdmJC1A2zNzSzhtslNWWNjKEtcceYt1\n" +
                "5lfxS/cBIzJv8qLSVwsd136Wa3g=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID7zCCAtegAwIBAgIBATANBgkqhkiG9w0BAQsFADCBkzELMAkGA1UEBhMCVVMx\n" +
                "HzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEzARBgoJkiaJk/IsZAEZ\n" +
                "FgNnb3YxIDAeBgoJkiaJk/IsZAEZFhB0ZXN0Y2VydGlmaWNhdGVzMREwDwYDVQQI\n" +
                "EwhNYXJ5bGFuZDEMMAoGA1UEBRMDMzQ1MQswCQYDVQQuEwJDQTAeFw0xMDAxMDEw\n" +
                "ODMwMDBaFw0zMDEyMzEwODMwMDBaMHUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZU\n" +
                "ZXN0IENlcnRpZmljYXRlcyAyMDExMUUwQwYDVQQDEzxWYWxpZCBSRkMzMjgwIE1h\n" +
                "bmRhdG9yeSBBdHRyaWJ1dGUgVHlwZXMgRUUgQ2VydGlmaWNhdGUgVGVzdDcwggEi\n" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdZjCEq8H9mVwzW0tJkvsOuE4j\n" +
                "+D3LoEUE2bh5sopUAfj/IOB3xwajLwL3VX4joJQkD/D4efvZKh4pzkHnbC9s82PW\n" +
                "4HbKW95X1n2s85JFrMYuPGxzD4pDQcHWeptp6NM4iP2nxj/cc3kkxcov30hnk2lq\n" +
                "mmr3FNXYIJ6/D4e1AgGgZjikNwKFHqiC5b70bZW6QbUTfQ7PtsqsCb2tsLvDreXS\n" +
                "lBd8pLnB4b+czEFdcgXx9vVPEJf0tWik+k2dO5EbXhEFp9TB4/oOAPz/6J5sniSO\n" +
                "IkrRfwidMyUAn4/iUj9nzJ1ITJ3ffHhhOpAmEBI9S5yg8ntzwh6zKuxwp/HNAgMB\n" +
                "AAGjazBpMB8GA1UdIwQYMBaAFPBRGGLvzkHHt7BndGsCvDIKM5nrMB0GA1UdDgQW\n" +
                "BBQiXTJuQyIRmwrQGxx/oAX3WiwjvTAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAw\n" +
                "DjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQAU+rnqd3Fx/GnRGW1S\n" +
                "TkL+CqF8rRHHfVoi+TbwLpbcLltQPiJSm2OzYcPaxR4Q+qbVevA0aLTHFUrKb+dJ\n" +
                "yX5HIC0Mw1NgEoyMmgqBtxk6qsxawpxtSuiIrqVwC8ZSJA4x5r5OsVwm3BTu4yIG\n" +
                "BecgzQPToPTzkLpy+miylicd6zUotkx1/fk9H22Noi6CqTea0leemThYEf4UdiDN\n" +
                "txAI2gGY0++Pg4xS166It6G4VnNsIPF/HV684iwAO3FPGgtxPpu6chf1Z/9D9EZ/\n" +
                "bVHah6PIQS41hrUKp2dr9rTX4Jbaay8hg9FT4b0Uk4hSJxaDvEO/CcqLjK3HR2lc\n" +
                "CE8y\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(RFC3280MandatoryAttributeTypesCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid RFC3280 Optional Attribute Types Test8" {
        val RFC3280OptionalAttributeTypesCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIID3DCCAsSgAwIBAgIBYTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowgZ8xCzAJBgNV\n" +
                "BAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRUwEwYDVQQH\n" +
                "EwxHYWl0aGVyc2J1cmcxDTALBgNVBCoTBEpvaG4xCjAIBgNVBCsTAVExEzARBgNV\n" +
                "BEETCkZpY3RpdGlvdXMxCzAJBgNVBAQTAkNBMQwwCgYDVQQsEwNJSUkxDTALBgNV\n" +
                "BAwTBE0uRC4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/fMlDz5JD\n" +
                "/7MBJmlwT5o5VSaKNzR9atn91c7krfu5XtXr/o5sYmEj9KjxxFi6lj8aK2Cg/euN\n" +
                "+pnkVq+hDpPfGCpH61mSiEqTUl0IoNGe4OvOVzb4TSJdH/yK1MzWp/j+dsad/xk8\n" +
                "nvkjKopwAnEDBysTXO6aBQOYFvnQjmCSGBI10Ol8y82eBRIbs6YJOUWNwcM1lbPv\n" +
                "Xrv0xQjFHKTmUQI+FdL+GMS0bA9KyKUrNaJV+wjkUHLl4VJ6KqfXJHDdlljnyIuv\n" +
                "I+aiCPLKSRlvyno5Y6TqiNEfSt/TZ5NgULmuRVN0Co3vGQ1SamZktsVMMOwezYfh\n" +
                "HiI/iqJlgxPDAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ\n" +
                "XahmMB0GA1UdDgQWBBSbbm8/iqf057WMMVvOmUuRHHx8vTAOBgNVHQ8BAf8EBAMC\n" +
                "AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ\n" +
                "KoZIhvcNAQELBQADggEBAAj6iDDC+RKlBUsSdZe8/5Equ2UzaVj2P8vP/zYIsxWS\n" +
                "rJwFkWh4tzgjH73ebe2IgZ5J+C2TvQ1jyfAOR7QulIc6Sm3izVdPLviV4OYA8goi\n" +
                "1dWKfxz4Aj6FATriooSFmH04ovaFUojUwdqlUkVJnWZTyLrIZJLMrIeP6BDHBjHH\n" +
                "R3EivHM+Wrz3Jv8s3+wA63dVTfDRn/zC1ngjUvbaQc1XFZKl6nuRFB9EyCz2oAV5\n" +
                "EyJqI8K12JJqeAwdOSg//FhTS8tQPrYe1XHT8a4yjKj8HXX2PXl9l1N9gXJ1+T6f\n" +
                "Bmlx99K0UFrm5Ty7bfhLgjKoaBiFKjiLUDLzGkHaV6M=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID+jCCAuKgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBnzELMAkGA1UEBhMCVVMx\n" +
                "HzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFTATBgNVBAcTDEdhaXRo\n" +
                "ZXJzYnVyZzENMAsGA1UEKhMESm9objEKMAgGA1UEKxMBUTETMBEGA1UEQRMKRmlj\n" +
                "dGl0aW91czELMAkGA1UEBBMCQ0ExDDAKBgNVBCwTA0lJSTENMAsGA1UEDBMETS5E\n" +
                "LjAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMHQxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMUQwQgYDVQQDEztWYWxp\n" +
                "ZCBSRkMzMjgwIE9wdGlvbmFsIEF0dHJpYnV0ZSBUeXBlcyBFRSBDZXJ0aWZpY2F0\n" +
                "ZSBUZXN0ODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnWd2qWpNr5\n" +
                "EB4D/X04sWYwHk2O/sNfaCRnyPOdRa04rEwDbcqICC6y40U0nyDFc0EzBcCHVqts\n" +
                "Cn36EI4hpnibj2BRybDIo2Ntb2PH6z0BbQUfPY/X34yJ+k9uFEBRRL9gNyQQH+DB\n" +
                "mgN/HoQ2UOiGvmdNJY9Sc5f3srgi+0TLs4W0kaeW3l1/aFImKPBXIE6Dwhqr8x0I\n" +
                "i2MY1piu/TN6llFXukOkz8cZihj8hetOPNTJPcSjQ/LB+WQpfyQ2RsVlpIhy0tf1\n" +
                "PpBpWrc9Jljx11MT0uHCJ6Agq/cqO9NxBWR6NN2rCRq+8JwOgBNS+5qH2hex7taN\n" +
                "QpedWsWMxk0CAwEAAaNrMGkwHwYDVR0jBBgwFoAUm25vP4qn9Oe1jDFbzplLkRx8\n" +
                "fL0wHQYDVR0OBBYEFFo1tItlb/GOrVNgqo0jnqVlFChDMA4GA1UdDwEB/wQEAwIE\n" +
                "8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBACLn\n" +
                "LA2yu+fl/z6CAe91RJeh1g/9ffXA81W2NjqtgRF9p3ryT0M7ZVhVd8qmN4ZbTB+O\n" +
                "lTTIgspdcgCFbX3SzH6MFOHmTmIug7hsuBkR6xhs4fGbGb9MqbAbcsUhqNSC+EQ7\n" +
                "35+ti62crD1Ew83xhOn8rPqCfKj8cRlac15f5w05TItgB0v4/laFMQwGGvJcvGkQ\n" +
                "j8iWgV2SRug22qujOb7ZH5rTJJLWvZ6oLNasiyB+Fe6ExidWRU1YKmFNWrP1OEe4\n" +
                "Hll70oWjXGLo/Ilkw8dJDe2wxLgktazED5eBsqfS8wPCTHkaaM/YAcbDmlbXvDED\n" +
                "Rk8uUmjfR/dHOtIdEb0=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(RFC3280OptionalAttributeTypesCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid UTF8String Encoded Names Test9" {
        val UTF8StringEncodedNamesCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgjCCAmqgAwIBAgIBYjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoMFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFjAUBgNVBAMM\n" +
                "DVVURjhTdHJpbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDp\n" +
                "FMdocNgWHWbH/yYbXj7cmkTMmrDj9bXTRwJQZM2I/fcTefta90CFELGbDX2RdtAn\n" +
                "jlSJqkydCKjhhkKXfMQFXJDlM6MQLf4rcQoxEP8UI2KmnbkfEjfsyGBxnSEFWe0w\n" +
                "ZZ8z5eWrLyIFZYk4x2Zyc5da7szsOnu63qN15kAJRf5qLTQyBVbvG6pJrOQaDF9I\n" +
                "SrgA1Sj7UW2puqZ40fbX20zywWxMEIeX3QO1Ho4onJXwi81/LMjZ3CvWqtEuGXo+\n" +
                "D5YJHhMBx2Ok777u34ahScf3f6h5YBixNf69RCCIR41Hki/aJ8Uwir0Ylx9mdT0X\n" +
                "fE42LskS6v/MsFLGUpCtAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWu\n" +
                "vnW2ZafZXahmMB0GA1UdDgQWBBQ7Z1tE8g2nSH1zKYyTn9Uk4xJgJjAOBgNVHQ8B\n" +
                "Af8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMB\n" +
                "Af8wDQYJKoZIhvcNAQELBQADggEBAAP+S9Kl9ocPuIY66PoFSDnkqzKGoqlaqslJ\n" +
                "7f7oUQTUwVKGx6hxk18tUGCR4rof/JpLBj6fjYLcfAutev7e/ZZPf+X6X9QlJW3R\n" +
                "pqLCIcGfa4k0LdLLDIYUGKu3YzeByWf+7AHjrFarwSxlZSHwooknYMokxMrgroLo\n" +
                "Mkawy5gZSMyykCgLxWtJdCHq/lSxLnseGN7Xfpa4Yr4ST9GgF3oyvMVIgp7jJUAw\n" +
                "15Yjtfpu0NJ0EkWbLp3k27UG12xDzC4XZUfco5ecXy0Iflj1USDPXUMJ+9etyJQo\n" +
                "6ctOAf1vXD90OpTS9YynXwm4VCqRRISItnWSbLIvEK0zg+YrB1U=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmDCCAoCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBGMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UECgwWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEWMBQGA1UEAwwNVVRGOFN0\n" +
                "cmluZyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGwxCzAJBgNV\n" +
                "BAYTAlVTMR8wHQYDVQQKDBZUZXN0IENlcnRpZmljYXRlcyAyMDExMTwwOgYDVQQD\n" +
                "DDNWYWxpZCBVVEY4U3RyaW5nIEVuY29kZWQgTmFtZXMgRUUgQ2VydGlmaWNhdGUg\n" +
                "VGVzdDkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiQyHe+Qlww7JG\n" +
                "F56OLnXVa6/PwDW5nMyghTVjB/9SVbOF2cOOtFS/pGw9Qbc42wajSZuKP0tEBph0\n" +
                "SkZlyhpyHwcGn2UMrWolAnAGDugxr83ijb/AElL+Orzm5lxPcuVG8+D1w9EW7JOq\n" +
                "I4iwhHe70XKdM5RaGRzQpQmfvGMuj6VsMUJaIv+9/5RLycevwNEZl3yiLTV6APui\n" +
                "hoI8LQQc9C+YQfAzRqz+e9adZIBayMhshpAJtgZ9pdNRPiUXt/NDw4jSbHp+fABs\n" +
                "3x0i5GMDGBQMI44rUVY4odIM7GcIFZ14HyLY0stkp2PsHCvmd2DBS9QbCA7rWhHu\n" +
                "8gcdQ021AgMBAAGjazBpMB8GA1UdIwQYMBaAFDtnW0TyDadIfXMpjJOf1STjEmAm\n" +
                "MB0GA1UdDgQWBBS4qOG97iGSGhivTSqPnNsjcsGavzAOBgNVHQ8BAf8EBAMCBPAw\n" +
                "FwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQAeayIn\n" +
                "ZVW7XoaTBtQWUmvNBO3bMOq/FsCioTns6lSZp3JeTMG0yj6HmxJGNLuDNMzcfN88\n" +
                "piQ7sfvNf+lcWb0gwdB2HXWTU4TcpAHUkn83Fid9og3gZv4YDh+fIQtcaL4/Yja0\n" +
                "cSDiy/OYHvV3ehEuTAnMPh8Utd5UI72eFwznL+7lFdJMp6IMTa0GD5iVjkYDSOE8\n" +
                "CBFv1vyFZOpiM3US56Kuo93VQdDUSXZdbHphgddospcnlW1fQ4wvMUTZpXeqcbu0\n" +
                "kDqNIM10ooUbnkpa8Zsf1aOdna1p3GcFyJTdpKiellXrtc52azNxwHgPwvchG4k9\n" +
                "RqHAGNJlDwsEHMB2\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(UTF8StringEncodedNamesCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid Rollover from PrintableString to UTF8String Test10" {
        val rolloverFromPrintableStringToUTF8StringCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDozCCAougAwIBAgIBYzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowZzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExNzA1BgNVBAMT\n" +
                "LlJvbGxvdmVyIGZyb20gUHJpbnRhYmxlU3RyaW5nIHRvIFVURjhTdHJpbmcgQ0Ew\n" +
                "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4QRMT6RUZ++ck88kdTGnL\n" +
                "uSGSuRwF1A+WPYdNn2ItthG+kgAL5BraUBXDMDCyGWMp+gYPpm4vSwcBO0oMLT/6\n" +
                "LINM4btQkIZ6yZs73RhuAtH+Pt9P1E0w0PQETJwg6EG6RngWSMpZTf4oWNCMxr2d\n" +
                "QYQKg1fKNicpMBiPTtexH6uwyCbNGbZPMAsMCtLoP62gUCzwNs1u1PzzZmwTWHw7\n" +
                "1WY3kaRbOsRUHMMaIqgZQC30/9mY1WPHiBbmkHQzFpwC8r4fGiHFwX/LWBFnfOnZ\n" +
                "1xxmKKsUr0agKy3SkMyqoSANHJNMrZruFmQu2ZVE2nZUiHvHn6GTjVSc4QsqhESv\n" +
                "AgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1Ud\n" +
                "DgQWBBS1bU8oP8e7sZikqaXQqFteSnSz5zAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0g\n" +
                "BBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n" +
                "BQADggEBAEIpMIiOeUzWzRx5RExhSxK7MtakcVAbTjjlHWSlTuNWvkEpo6hbj5re\n" +
                "iUeRe3dt9mHKa2/rrTIfzd44IXmYGb/E+n7C1jzlxOTlUrHrVv+CHtANcON2lsNq\n" +
                "/ZtThy/HisC1FqEM2rQMfsSmHXzDwgsEFDCZU/wTbWZKig1oNpkUPLXa39IRqBIZ\n" +
                "WVu3HtxMAlFccm5Olp/gE0EvqFgzufYSllZU2khgkCaQjLlbqw9aSiNUZob+pY1v\n" +
                "asyGwpiBv9AqeYODTRd/2GCmkHTt2k8aEXoY2ICb6Wzqb9TDQG5Ea1h2y31C4UaY\n" +
                "HuU+qfxmwTT1sIiABlmkzTWaOWw5qmM=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDwTCCAqmgAwIBAgIBATANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UECgwWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTE3MDUGA1UEAwwuUm9sbG92\n" +
                "ZXIgZnJvbSBQcmludGFibGVTdHJpbmcgdG8gVVRGOFN0cmluZyBDQTAeFw0xMDAx\n" +
                "MDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMHQxCzAJBgNVBAYTAlVTMR8wHQYDVQQK\n" +
                "DBZUZXN0IENlcnRpZmljYXRlcyAyMDExMUQwQgYDVQQDDDtWYWxpZCBSb2xsb3Zl\n" +
                "ciBQcmludGFibGVTdHJpbmcgdG8gVVRGOFN0cmluZyBFRSBDZXJ0IFRlc3QxMDCC\n" +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANP+zCkHFztNGKS2jaNu7j8g\n" +
                "O86LJI1CRdWLEfDjiqoCvEr7LrXRQsQGW79/GqtxZN1fu9yt6eaUBvusLU25JLX2\n" +
                "johJWagbI4YJdao06kQWtzxk0JRIo8uOjEhAB5cnykYAlGAaRPm5BvMSGlLuMcYw\n" +
                "80TpK0MtBIoHIa0yqU2+/CWwwFsGf3OKQQGjxpYx3rqL6cC69ybFfREYm6eaC2Rj\n" +
                "H3bpKBEN1P544WU1ZKsaO3bZXXXa5+ehX+eSalHdOh3KMJxRej+D4xgsi+E9oO8w\n" +
                "4Rixi9Hb90oZwiO3i2zdgFCd/iwVxk9pUjVAKebqBI4Dv8wsIpF4Rq+/qd7LJxEC\n" +
                "AwEAAaNrMGkwHwYDVR0jBBgwFoAUtW1PKD/Hu7GYpKml0KhbXkp0s+cwHQYDVR0O\n" +
                "BBYEFCTnhF1EvGRoOoQ2I1s2vDsOw+E/MA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAE\n" +
                "EDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBADB62jvyJnKCkLza\n" +
                "PWHwcjg5rGeRYTcD/XvxR3C9e7taMrg8JDied+IzbkItPOq80bqB+mScXHlWSk9B\n" +
                "mz7fg/Af1Ip6ryhw/fISLxnvHXNWaM7hJcyGJjH1uCAmgm91EDfn7KKJXqi4CkH8\n" +
                "cBJATJuohy+iUUlOru0ZoeiQGLWO0nkmw+GeIZiztXaKXKmoV+RGfLIAFEwuS33s\n" +
                "GmrHob2DjHBIgAa9CcP03DOTtW0k/JH62NupGQDciY/dBj75I7eX6tjMGQn0h1vf\n" +
                "up27UzRHUjBMh8NYpmnvK24LRYQMQC3TaUbaz6gsD9cNYMFiFBXa35AcDjr/Zanf\n" +
                "H8YRcS0=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(rolloverFromPrintableStringToUTF8StringCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid UTF8String Case Insensitive Match Test11" {
        val UTF8StringCaseInsensitiveMatchCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBZDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowXTELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoMFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExLTArBgNVBAMM\n" +
                "JFVURjhTdHJpbmcgQ2FzZSBJbnNlbnNpdGl2ZSBNYXRjaCBDQTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAMG57Err72Y6WVucCLR9vA602ukJ6SGG/fkb\n" +
                "m3MdFHFnIlwT4bTqW1vVDbWM6JGk6Ats6QdrCKHNepQUivKcTaOf+Z/AM0PF8Dm+\n" +
                "/46w0H8slEycnjp9R9kVq3RxnfaCVUuoT1GUilrIl6lzYDbLmk586gIDHiKIB6G1\n" +
                "EB1SbyGrTqUb4PbX6BqTP3DyMagsCXbB9mQtdub0TMopxgLPhx8c9J4dT4GT2zN0\n" +
                "YhDhy1j2u/fe2IaKQ/cBYdli4UpwlJzvBQj9DChrTUeMU0bE8LUUot/+SgUnJzgM\n" +
                "00LL1siFE9AwjpdtBp5TZWaGrGJGNWEzV/jiRtmiAKoU5qMr07ECAwEAAaN8MHow\n" +
                "HwYDVR0jBBgwFoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFGDfGNHK\n" +
                "qVCSERchRNJ39Wqtpr54MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCG\n" +
                "SAFlAwIBMAEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAXDmk\n" +
                "vYzphSsHCShEza+0eHMVa+8vfRkgzCtHfL9ch77919MmuIbJSuXxvmkV8bwBdIzV\n" +
                "A9prai62c2AAPgDGlFpQZwUY+ead5JWxnqhdhSbQQ82GguuLbjmwV6nWeGuNwX7S\n" +
                "bLSt7V2e3aiijWB6grarbdReY0c4r2gceiNA5QpPmFpnL1r10GnE+hCf69dLJGpp\n" +
                "sAzcGVaokxKA8DZhgag+Jv54NOMZKH6o0L7p4peM0l/acVHkLNvHmZTgjrz9If44\n" +
                "wHSFmxIjghuYD5gEKtvxUm7blklS1anKqrHHaqQfYWyJfBAwdgNjiASvlfypETzz\n" +
                "801tbjXPclw1G82spQ==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDvjCCAqagAwIBAgIBATANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEj\n" +
                "MCEGA1UECgwaICB0ZXN0IGNlcnRpZmljYXRlcyAyMDExICAxLjAsBgNVBAMMJXV0\n" +
                "ZjhzdHJpbmcgY2FzZSAgaW5zZW5zaXRpdmUgbWF0Y2ggQ0EwHhcNMTAwMTAxMDgz\n" +
                "MDAwWhcNMzAxMjMxMDgzMDAwWjB2MQswCQYDVQQGEwJVUzEfMB0GA1UECgwWVGVz\n" +
                "dCBDZXJ0aWZpY2F0ZXMgMjAxMTFGMEQGA1UEAww9VmFsaWQgVVRGOFN0cmluZyBD\n" +
                "YXNlIEluc2Vuc2l0aXZlIE1hdGNoIEVFIENlcnRpZmljYXRlIFRlc3QxMTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN29zJK6hFJG5nAuyoIXSLM7XSRW\n" +
                "O5FCiwm1id6V5ELZnaiQN5PtY7ZzOdQ5Rymo60UCnsnp2Ylg1OYh82GfvKG7gZS0\n" +
                "xRwA/3Z5veLZsYhuqm/yixO3lfbmQRb1axDgfudVwUnwdQlvXjXPf4EsIB5WIAIv\n" +
                "JYryutqJNIn3VX5BeI8luQX2ynlkc1StTCeUMnXYT26X2GW71m0hn5RsSlwHayo2\n" +
                "HXVULIt5ojyGoatCESTbN0kmPXKJQTwV/KmER9Ual9Zb4BKvdy0Kbs/SImNzmA3a\n" +
                "VITJ/YMs6BA0OshD39ZkqvDF86aCConG69VXWF9ASOmClC/asa9AyHvDAKUCAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAUYN8Y0cqpUJIRFyFE0nf1aq2mvngwHQYDVR0OBBYE\n" +
                "FKzudXSiTCM93NKYuEBr9McOizZqMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAEv6NJ3Kqb+fORfTmqBp\n" +
                "z/UIu+rdVqUmqVOc6VEG8hrOWOUjNHxb+DQHwWSM52s4ednWj4iOrERBtqI6I9+L\n" +
                "Ja1yCa1i84KLowhew/iH8fgFqLnuoqiQ6SXvY/z6hBIHgOSZ5LI0yF7Zsw7R7JKc\n" +
                "S4rpOI9lrXRPHPFv51Up7Z9BUNv1QOU7dlLAIwXXKvEETuYD4rM25w2Jz6ogfdXD\n" +
                "Rs/B2OAm5lKTf/ZNeLtF30oyNPHPol0DvAQO25oRtrguOShdluY++kWqDXlVMetI\n" +
                "y5xJ4/n3p2W3V+S56jwwok+627UoDYUqS4ulQtix30lcWi2O+UqYgFnNWJxwa+Gj\n" +
                "zp0=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(UTF8StringCaseInsensitiveMatchCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is ChainValidator } shouldBe null
        result.isValid shouldBe true
    }
})