package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.anyPolicy
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.CertificatePoliciesExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.Qualifier
import at.asitplus.signum.indispensable.pki.validate.PolicyValidator
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

@OptIn(ExperimentalPkiApi::class)
val PolicyQualifierTest by testSuite {

    val NISTTestPolicyOne = "2.16.840.1.101.3.2.1.48.1"
    val NISTTestPolicyTwo = "2.16.840.1.101.3.2.1.48.2"
    val NISTTestPolicyThree = "2.16.840.1.101.3.2.1.48.3"

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
    val defaultContext = CertificateValidationContext(trustAnchors = setOf(trustAnchor), allowIncludedTrustAnchor = false)

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
    val p1anyPolicyMapping1to2CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIFLTCCBBWgAwIBAgIBNjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowVDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExJDAiBgNVBAMT\n" +
            "G1AxYW55UG9saWN5IE1hcHBpbmcgMXRvMiBDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggEPADCCAQoCggEBANzb/x7g9fYUZJHLawFd5dXdaTd5QI6b394FF+evA8+llsAl\n" +
            "r9BqwYe139iY9+RgTrroi8KRFeZaXndYBYANU+fvhLqFWAz3TK0nW+otpf5bJiCZ\n" +
            "27slpFJEINgrpLQpENt12YVkQ60alGIrvYIxjZkOrhbgwHqTxxMc98Nqdf9PXmaY\n" +
            "5qai+dWQ7RMewnkoX6bx1TmgQXOT17qlbOfyuAnYM1oabX1+86XEw7W69i6Cb8/z\n" +
            "/VkC6qeRbV1Pmu3lVRsoidYwGs2cwAyMOzz4MpTflSk3b56w0MbmHhyflr+/d5yp\n" +
            "mNAkE5dTqu0f4GZEACFbA0AP1qSbtgmG6vc1g5ECAwEAAaOCAhcwggITMB8GA1Ud\n" +
            "IwQYMBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBQfAigoMo5KhPi4\n" +
            "i0HxXXvoJVJrhjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAMBgNV\n" +
            "HSQEBTADgAEAMIIBeAYDVR0gBIIBbzCCAWswgbkGCmCGSAFlAwIBMAEwgaowgacG\n" +
            "CCsGAQUFBwICMIGaGoGXcTk6ICBUaGlzIGlzIHRoZSB1c2VyIG5vdGljZSBmcm9t\n" +
            "IHF1YWxpZmllciA5IGFzc29jaWF0ZWQgd2l0aCBOSVNULXRlc3QtcG9saWN5LTEu\n" +
            "ICBUaGlzIHVzZXIgbm90aWNlIHNob3VsZCBiZSBkaXNwbGF5ZWQgZm9yIFZhbGlk\n" +
            "IFBvbGljeSBNYXBwaW5nIFRlc3QxMzCBrAYEVR0gADCBozCBoAYIKwYBBQUHAgIw\n" +
            "gZMagZBxMTA6ICBUaGlzIGlzIHRoZSB1c2VyIG5vdGljZSBmcm9tIHF1YWxpZmll\n" +
            "ciAxMCBhc3NvY2lhdGVkIHdpdGggYW55UG9saWN5LiAgVGhpcyB1c2VyIG5vdGlj\n" +
            "ZSBzaG91bGQgYmUgZGlzcGxheWVkIGZvciBWYWxpZCBQb2xpY3kgTWFwcGluZyBU\n" +
            "ZXN0MTQwJgYDVR0hAQH/BBwwGjAYBgpghkgBZQMCATABBgpghkgBZQMCATACMA0G\n" +
            "CSqGSIb3DQEBCwUAA4IBAQAJ4zsy9qL10OJy/VRk1NA5w+0ncD1kOXO0I2cHSqA6\n" +
            "wtQ6I23JPRgTutDfvR6ktvdBRfkeCwYHPVHHx9zrvfnk2MIAfdDeo93IVAqJEumo\n" +
            "LIoi+XEUWpRH1MiJbl74CndIpdc7G8H4OOagqMz1p2XsZ4K8RpF/H0WUYGvWsX7g\n" +
            "78EjEraD0D9PxWr1Na7kfnHoYxrqd/fmRYtnCwt26jO8A1DHXgrWerE/fnUlTxM5\n" +
            "tHHN1OMOlggOimhGvJ2pn05BdXIhVtmWCdFo6+pTcyWYMm2IvOrzEaQtnGf3Zefp\n" +
            "lObeComhN1QW5zDtLnzOhHUHc1t4deRAIN1zhE8vpYsG\n" +
            "-----END CERTIFICATE-----"

    "User Notice Qualifier Test15" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID/jCCAuagAwIBAgIBKDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowZDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExNDAyBgNVBAMT\n" +
                "K1VzZXIgTm90aWNlIFF1YWxpZmllciBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTUwggEi\n" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkS8nR/CBLM63BPIASc/HIZLUW\n" +
                "rQrETZeD+GSRfJD3dhns+yVXSruNS2NJIb9GJ9LWU759uH95jMGlAmFltbdAyd3a\n" +
                "AZPqvAYmi8ZpCbS5z/Sg527s6XPHGFVjLWKuK9CN9GUyH0f9dJ2nuQTZESbELZRT\n" +
                "2G9GOnaPKaNet9jlmu3ykU/av1UNoLOoJ//8hXRh3NaeI6c/3i+N2eTD26t4IpkF\n" +
                "+ez7xx9ULTjw3xAVBJDJK+iz0KdfZcVj65ahMEmhWZRBzn1qLhboVnK7cRzCNqWz\n" +
                "XF+bIVRt04TaZ42laGLqPKv3cJK7KdRYxt9gRVNXnthIP0U8RODhAKlBeAALAgMB\n" +
                "AAGjgdkwgdYwHwYDVR0jBBgwFoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0O\n" +
                "BBYEFI+sjau3vxyGncC/k0TJSTOkGg/HMA4GA1UdDwEB/wQEAwIE8DCBgwYDVR0g\n" +
                "BHwwejB4BgpghkgBZQMCATABMGowaAYIKwYBBQUHAgIwXBpacTE6ICBUaGlzIGlz\n" +
                "IHRoZSB1c2VyIG5vdGljZSBmcm9tIHF1YWxpZmllciAxLiAgVGhpcyBjZXJ0aWZp\n" +
                "Y2F0ZSBpcyBmb3IgdGVzdCBwdXJwb3NlcyBvbmx5MA0GCSqGSIb3DQEBCwUAA4IB\n" +
                "AQChryB49S/BVXmv59TlPzJpVgyW7PstcWfaKX7Qbf+Fg3ef50OA33+0qT3dQz+L\n" +
                "jU0f8PMJWfrez15/izohc/YZPY2sSiJ5zxzvPGliVqDeHqnJTUc+nWT0yeghmBHZ\n" +
                "NEoNVSVJvSZEesXLCmNQh9g3BVZ02jx3dRDfRFesaxtTIZt8pazRdmV70aXJlT5y\n" +
                "f0AiFsHzrk818uk2bTipjZcMGExgV8umbnjbk0P3UQPnhRGmGGH/GNytL1xO0br9\n" +
                "dtwq0BNDWMELT/Ba/LhebotG1YUCYdd430Z+BxKk7gkwhFADdkbil6yFDmgRsYSY\n" +
                "wnOpVqmDrMivVvLaqUozgsX6\n" +
                "-----END CERTIFICATE-----"

        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf)

        var result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true
        result.rootPolicyNode?.getAllSubtreeQualifiers()?.size shouldBe 1
    }

    "User Notice Qualifier Test16" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEdTCCA12gAwIBAgIBEzANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGQxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTQwMgYDVQQDEytVc2Vy\n" +
                "IE5vdGljZSBRdWFsaWZpZXIgRUUgQ2VydGlmaWNhdGUgVGVzdDE2MIIBIjANBgkq\n" +
                "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAulbeEb7O7vcRacycC6/ainA+gXxpoasZ\n" +
                "XBUoU+G+eo5d5yCnsyZ9FSguMM3v3bqc2THkHxZq3/9c9/MCwBEai70AQwS6Etvz\n" +
                "GGIGk7MAw5c8gWi8smIHMMPY1Zqc6nQjFr1qxk/Bj/nWUKeqMhCWs6S69Q1IsmKN\n" +
                "uwLYO7/DjcKwc9jgiUXVTcNCnkbzUIdjBM47jsyXrpMwP47D3dMYTA9bzBjKj/fN\n" +
                "IFS3gLv4JqTu755LxVBjjjpg7Kt8EMXDSrNci5ZyViGdfitwd+F3MU0Q1Q/fnadi\n" +
                "QpoASYBVHDx0scpwHSt/imQQz02Rfoo5cQ6SS2RVvXhZ6B4YfMm99wIDAQABo4IB\n" +
                "VDCCAVAwHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2lEHIUUfWvOskwHQYDVR0OBBYE\n" +
                "FAIO7iA6v+sW5S3aaqon7HTHzsOAMA4GA1UdDwEB/wQEAwIE8DCB/QYDVR0gBIH1\n" +
                "MIHyMHgGCmCGSAFlAwIBMAEwajBoBggrBgEFBQcCAjBcGlpxMTogIFRoaXMgaXMg\n" +
                "dGhlIHVzZXIgbm90aWNlIGZyb20gcXVhbGlmaWVyIDEuICBUaGlzIGNlcnRpZmlj\n" +
                "YXRlIGlzIGZvciB0ZXN0IHB1cnBvc2VzIG9ubHkwdgYKYIZIAWUDAgEwAjBoMGYG\n" +
                "CCsGAQUFBwICMFoaWHEyOiAgVGhpcyBpcyB0aGUgdXNlciBub3RpY2UgZnJvbSBx\n" +
                "dWFsaWZpZXIgMi4gIFRoaXMgdXNlciBub3RpY2Ugc2hvdWxkIG5vdCBiZSBkaXNw\n" +
                "bGF5ZWQwDQYJKoZIhvcNAQELBQADggEBAEgyglT7PF+xqOPfkWfZD+B87fSODdlO\n" +
                "5HPCqZySlix3IrkJHL4/acMADY4mY4zP+W8dUawWs/6ud2ECVn2UJLQcpzo9n9yk\n" +
                "XS96jwdihJG4cgOib7T2PUk0CiGU1kkPBHmUx8oCXqMKF3xSvK80fXZdByxg3o1Z\n" +
                "2MG0xxqok7SNJ9YhFjMNl5KogfNEiY9tsTzM6zPTVqU0iSUSXCW7PQEPAuBhI+Le\n" +
                "pWFaEPdjZBN7rRGzK8w8YDCBG5d/O/e91PTMO5NtjmliHkFu8XkGu/WBPHOx9qH+\n" +
                "IyTErE6J6vUrWZ2ycgmrf8Apd62mBopcR48xY9X3acE7QcdtgEe5/Uk=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        val qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
    }

    "User Notice Qualifier Test17" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID8jCCAtqgAwIBAgIBFDANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGQxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTQwMgYDVQQDEytVc2Vy\n" +
                "IE5vdGljZSBRdWFsaWZpZXIgRUUgQ2VydGlmaWNhdGUgVGVzdDE3MIIBIjANBgkq\n" +
                "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtgx/GESPgx+f2iTkGzayiIzcQFdPHoke\n" +
                "X5w5e985q9OYBAGQR8L3z1N5pzoNK7KdyuLfTH/5ymU9F/TAfMjzVejFuojT0kkM\n" +
                "YKn0WhTpc7lL43DesIDLfpmVxNseL/AfP52wP5KWfzLPeS12xOwVkkYYk+rXBCsy\n" +
                "4Wajt7CR/OgYVVZqr+l4eoMZXC8QkbRzpqYMRsPDLDDjWM8TrdJWOcm3fS33pgTA\n" +
                "IYaihsgfIPRAMV6xbTi970Z5nqjWQuQ1KzdvUe9FUfGNeUDybmOJSIVzQjbNpTQs\n" +
                "rWQYzW9BcSlCjiGCDi01O8tur062uk7V6vtxQU+LDl2vW+etQZx07QIDAQABo4HS\n" +
                "MIHPMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJMB0GA1UdDgQWBBT+\n" +
                "LIExXNIznYNgktX0s3YpDGcmLTAOBgNVHQ8BAf8EBAMCBPAwfQYDVR0gBHYwdDBy\n" +
                "BgRVHSAAMGowaAYIKwYBBQUHAgIwXBpacTM6ICBUaGlzIGlzIHRoZSB1c2VyIG5v\n" +
                "dGljZSBmcm9tIHF1YWxpZmllciAzLiAgVGhpcyBjZXJ0aWZpY2F0ZSBpcyBmb3Ig\n" +
                "dGVzdCBwdXJwb3NlcyBvbmx5MA0GCSqGSIb3DQEBCwUAA4IBAQBfBRO7j1sk6/+/\n" +
                "03HPnqa/E694vMdtGy/K/d8K3mdRuPTcxNcT2gW9VnVyQ8rKwrtZn0oWjehifnvz\n" +
                "5DJCIrE8Qf03kY1rbCkcDsQ981Lbg4t11pzBqGARFVrAfzzeiKY1Q9EA7QPbpYvB\n" +
                "RANQsSXkCSjE3BPvHdz/1ZZeP+kvzNSb+vrXOs0MXA5eAmz6Or9bOak+XOUDZS8l\n" +
                "CrmEI6GRG8Coe8zy4YAbPy7uO7Zdvd+uQSEGDlwCDCtqQP0H2uWmNCstdAZHoJbi\n" +
                "RevpMviFe7MFOtYgpJhEwgmK3wNLDcaPgznv5qCuH378n6gXL5Kv0ehBd9LcWPv4\n" +
                "jZua3QQF\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)
        val result = chain.validate(defaultContext)

        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        val qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid == KnownOIDs.anyPolicy } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
    }

    "User Notice Qualifier Test18" {
        val policiesP12CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDojCCAoqgAwIBAgIBJTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowSDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExGDAWBgNVBAMT\n" +
                "D1BvbGljaWVzIFAxMiBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
                "ANRtyEq+rl+FhO+NHVJOJN2OiDDWN2do70bXRgbSRM+hytvZmhVtCwdDvrc66wSo\n" +
                "nq+/5yMnEMw2SXzpsk4beZflV5IWBVo2TF9jdoRa73FMzVcDIQigT6JZUIGJAmTc\n" +
                "VpfXbAhGXLpGdzCYV9GrkdWneOLn2C0vtKA9pyBO/60o1J5o3TMGfD79qU/UhZm+\n" +
                "Up0jlotpuFo/wi1dInTyTWLLwQTOLHl92GCON+jQ7myetjCy5OPSi/YetgO1ivmF\n" +
                "H6pPE7GClTgS9wKHlsdAKD/NvhJHRXKvUBV/IRo0wmYSbpPmDICaIEAT3jr9HV73\n" +
                "XN4PkOkI8byCf4uD5zjHA3UCAwEAAaOBmTCBljAfBgNVHSMEGDAWgBTkfV/RXJWG\n" +
                "CCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQU2F814prBNyomzoPMcw5wFSo64jEwDgYD\n" +
                "VR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDAYDVR0kBAUwA4ABADAlBgNV\n" +
                "HSAEHjAcMAwGCmCGSAFlAwIBMAEwDAYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAkmpY6Gpz8ttXcYTVjZJxtH5HBhZZ4MQjPYWb7Yoz1Fg64BUeuPum8KIH\n" +
                "+KoyJFYJPmQ46Gop3uqosBj2S3kZ9zmzOd8PIBYiCn5iNZ5GzNhKvyOICWWD4nzH\n" +
                "mIh0MLjON9H5aOKRPYqQj2R2vqyzqr5/YPPsbCAIj31a3XrEVN71161aPOn6wVMk\n" +
                "l8/NkC+xtLzqpFxNdRlaAdmf7eT5MRy6J4GC/lf+YKp6RaPcLQTjlzTjF4ABxDbj\n" +
                "57GFiSn5lzz2/eWvN9i0Eg6+LhCa42wJj2Iviruh+gVOqRe4eLjIyVcN3BwcwFCY\n" +
                "BlFoAnTVg0CnLeR4swMjKUmHU3n86g==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIE1DCCA7ygAwIBAgIBAzANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEYMBYGA1UEAxMPUG9saWNp\n" +
                "ZXMgUDEyIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowZDELMAkG\n" +
                "A1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExNDAyBgNV\n" +
                "BAMTK1VzZXIgTm90aWNlIFF1YWxpZmllciBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTgw\n" +
                "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC88AhCshO70EgmfJ0LoJAP\n" +
                "aEyUfJHUOk0+uSHgQxC+TXR4NZUZYKNeGwc97Cn80E3uoygIUKpOIoZLOmA4Xw5E\n" +
                "ZA9fZNmmT7cIzAjDXUJv6Oy03LcQ+2KNFRUIQ5d5y2e/InkkZjJNVqVxcpt8DdJg\n" +
                "VknMuYUk5kqD/uf+L8t4C57iEj0KlBQMgsXGa4vNVpc4dI9irDlTQVCPZofSchFk\n" +
                "5Ek41YVy+wDxDHW59/Opqr7VfXJOmFN0BxZ6NTW3VmXS4wWMV7ZTdi/YMVJVb/b5\n" +
                "0uCCk/JXtFGHlVz454T++Decj9xf6bFyCzNGJXzf0WMtSyuXVqT1jWsCo/hGzo8L\n" +
                "AgMBAAGjggGrMIIBpzAfBgNVHSMEGDAWgBTYXzXimsE3KibOg8xzDnAVKjriMTAd\n" +
                "BgNVHQ4EFgQU4DsI8hwak6jmjAEqCXZrCm8FaHEwDgYDVR0PAQH/BAQDAgTwMIIB\n" +
                "UwYDVR0gBIIBSjCCAUYwgZ0GCmCGSAFlAwIBMAEwgY4wgYsGCCsGAQUFBwICMH8a\n" +
                "fXE0OiAgVGhpcyBpcyB0aGUgdXNlciBub3RpY2UgZnJvbSBxdWFsaWZpZXIgNCBh\n" +
                "c3NvY2lhdGVkIHdpdGggTklTVC10ZXN0LXBvbGljeS0xLiAgVGhpcyBjZXJ0aWZp\n" +
                "Y2F0ZSBpcyBmb3IgdGVzdCBwdXJwb3NlcyBvbmx5MIGjBgRVHSAAMIGaMIGXBggr\n" +
                "BgEFBQcCAjCBihqBh3E1OiAgVGhpcyBpcyB0aGUgdXNlciBub3RpY2UgZnJvbSBx\n" +
                "dWFsaWZpZXIgNSBhc3NvY2lhdGVkIHdpdGggYW55UG9saWN5LiAgVGhpcyB1c2Vy\n" +
                "IG5vdGljZSBzaG91bGQgYmUgYXNzb2NpYXRlZCB3aXRoIE5JU1QtdGVzdC1wb2xp\n" +
                "Y3ktMjANBgkqhkiG9w0BAQsFAAOCAQEAfxyDNghdSbzgxj/mObFvvEknTx5cjRIo\n" +
                "L+CbP8ccGGrcfwJcbNEcZwlkzOSomEjsoROw4XPq6deZDC+x9McnYKYHwt78coSv\n" +
                "urgue6YqvDga1785BozPcJqN9iTK8babcOeWno7ZPRbUEqNFfpesSfUtRjBoFh4G\n" +
                "+YrgneWORnvSZFS3Cz4X0h3yei0ZMNdPK/Zkt35QymLrPxr9rAIzOewaXOH32+x7\n" +
                "bPgue6FhSz4na9iJQozynEsP1HSKRQdvm2E12ZYrE59hG7p2bqV/pUQSR8hZNnJZ\n" +
                "IUC2I3sFck92TKZsdnYQHv3NuCl758S7O3cXnF436gqP31KGAzgcVA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(policiesP12CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        var context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            allowIncludedTrustAnchor = false,
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne))
        )
        var result = chain.validate(context)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        var qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        var displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        var expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value


        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            allowIncludedTrustAnchor = false,
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo))
        )
        result = chain.validate(context)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid == KnownOIDs.anyPolicy } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
    }

    "User Notice Qualifier Test19" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIE6zCCA9OgAwIBAgIBKTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowZDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExNDAyBgNVBAMT\n" +
                "K1VzZXIgTm90aWNlIFF1YWxpZmllciBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTkwggEi\n" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD3E/MPmQrWuB1FwiUdy39Yth3/\n" +
                "GCiDQBK1HGlJRkREfH5qLLXoXoXkdTfKoKMz7jetlTwfqh61oQcAGrUxJ+1uXFFo\n" +
                "Z7rx39ZJy5WHoqh+/0KVFwVHzZlDjx6hRdDAV2wSH3CQA66JeGm6C/Q6seIPhXcs\n" +
                "5NiM/7x1f+gaA6OKQbFyPhErhvwt6T3MiJgdnATXneT285aE9ERxGxq6pMqLTwCH\n" +
                "7vnlDNq+86cr7qXwRxqgnrSyKZnd02g2aVRbQQbDe8GYJvn7FeJUruq33nGjYoUu\n" +
                "cq8taqkWaVEvlAc6rNHjXP9bFUC37Dt/q05ODc7g0vHQvkgVKkcLvIor8GFJAgMB\n" +
                "AAGjggHFMIIBwTAfBgNVHSMEGDAWgBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNV\n" +
                "HQ4EFgQUDU0KkzuR4M/gJ9ceN1sBfgKd6ZswDgYDVR0PAQH/BAQDAgTwMIIBbQYD\n" +
                "VR0gBIIBZDCCAWAwggFcBgpghkgBZQMCATABMIIBTDCCAUgGCCsGAQUFBwICMIIB\n" +
                "OhqCATZxNjogIFNlY3Rpb24gNC4yLjEuNSBvZiBSRkMgMzI4MCBzdGF0ZXMgdGhl\n" +
                "IG1heGltdW0gc2l6ZSBvZiBleHBsaWNpdFRleHQgaXMgMjAwIGNoYXJhY3RlcnMs\n" +
                "IGJ1dCB3YXJucyB0aGF0IHNvbWUgbm9uLWNvbmZvcm1pbmcgQ0FzIGV4Y2VlZCB0\n" +
                "aGlzIGxpbWl0LiAgVGh1cyBSRkMgMzI4MCBzdGF0ZXMgdGhhdCBjZXJ0aWZpY2F0\n" +
                "ZSB1c2VycyBTSE9VTEQgZ3JhY2VmdWxseSBoYW5kbGUgZXhwbGljaXRUZXh0IHdp\n" +
                "dGggbW9yZSB0aGFuIDIwMCBjaGFyYWN0ZXJzLiAgVGhpcyBleHBsaWNpdFRleHQg\n" +
                "aXMgb3ZlciAyMDAgY2hhcmFjdGVycyBsb25nMA0GCSqGSIb3DQEBCwUAA4IBAQBr\n" +
                "LA2+uQdk+39kZyVEG4nvYUgMB+UvSTIYiXq7j451qekOwMNV735tLSqtWCzrSGVY\n" +
                "rZ1tGVgnTBTf5LqcDa+lPVLEGeV1hUx2DnchGWPz8WZLtJXK6jVkG4wZlTx/xRR5\n" +
                "miliPtgwpdkYsUf9H9MVUmMpawPvf5s3ZNubE4dQxjwN5vN5xemuDrbcOyGYUkDs\n" +
                "+xLxGrkGvdikgVOUIRXP4u0Erh9uTXXwu/ZQK6ygsAYTSO6XmKIzTJUEjeBxzpaP\n" +
                "C/nEmljPBlHb680hA2nneeW/2HN+hmPpm0S9uDvwcIMNQc0c3q18lDNrhALaJQ1Q\n" +
                "8NBTUeL4fQnsCosYSygC\n" +
                "-----END CERTIFICATE-----"

        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf)
        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        val qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
    }

    "CPS Pointer Qualifier Test20" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID7zCCAtegAwIBAgIBFTANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGQxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTQwMgYDVQQDEytDUFMg\n" +
                "UG9pbnRlciBRdWFsaWZpZXIgRUUgQ2VydGlmaWNhdGUgVGVzdDIwMIIBIjANBgkq\n" +
                "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxhW1cwuWNSLDxdyrOixpJM40XwVpspuF\n" +
                "pFGa73TiwQs58B/3i6tfcGygyAAmZHYGoVKjIq5LvPbirMTnCYQ4AtPQwji0AuQN\n" +
                "KmCwSAAjY8WPT73mSvAEpv1C6vhWq/PYcNbHq1PHstsD+V3dXc/sLvBXAXPFEbD+\n" +
                "nyhBpIReB+efZ+fcLDRg34th2GezPq07Q7OsROHL+35JDqtMTPibpsNSSMETa8B/\n" +
                "5wW0j9PxpQqufx0sVPpSXtrcK7tn0dlhhwW6UnDfOQn1XwFqmYG/UQ7fKU/uIH1a\n" +
                "VQTAA7GnemZ4W0XFZwoccOOiDapNmlMfMIs4JhlkpUd1uTinDGCzPwIDAQABo4HP\n" +
                "MIHMMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJMB0GA1UdDgQWBBTu\n" +
                "QtAPWnapZlaIwYeYrcROSL3D4zAOBgNVHQ8BAf8EBAMCBPAwegYDVR0gBHMwcTBv\n" +
                "BgpghkgBZQMCATABMGEwXwYIKwYBBQUHAgEWU2h0dHA6Ly9jc3JjLm5pc3QuZ292\n" +
                "L2dyb3Vwcy9TVC9jcnlwdG9fYXBwc19pbmZyYS9jc29yL3BraV9yZWdpc3RyYXRp\n" +
                "b24uaHRtbCNQS0lUZXN0MA0GCSqGSIb3DQEBCwUAA4IBAQBqPx9Nphzkn+AqwLQC\n" +
                "tz30JaETh2kPhqKYjS7nUwbHzXz/zxeTrbQ7fRy6UGa8c1hyUtnekKZ7Y8T/cNAv\n" +
                "ltT+mxWtye/58YbSBSu+RdTJmJZIXbr7ZHFDwZC6gcMwvIuOe5nGRom6Yxthmciz\n" +
                "rCQ7m6H0VqkwZLMc2rKPKw9t2MmkUMHgxCIyh+Fa0x7jvkbe4cUP/7+CRr9tT7m+\n" +
                "Lh/94RYNQ16zIN/GCZnH9s4sjQLnOiGMQ41fa9zKngazpS4fMrxXPGc+NgFjVrk6\n" +
                "qZ+NRavzckQPEGoIZrR+8i4GFxfjFzTD+rGUiKHb/LO+n/+GKJhc3EhyIuHulRV4\n" +
                "eB2G\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            allowIncludedTrustAnchor = false,
            explicitPolicyRequired = true
        )
        val result = chain.validate(context)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        val qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.CPSUri
        val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.CPSUri
        displayedQualifier.uri.value shouldBe expectedQualifier.uri.value
    }

    "Valid Policy Mapping Test12" {
        val p12Mapping1to3CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDzjCCAragAwIBAgIBMTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHDAaBgNVBAMT\n" +
                "E1AxMiBNYXBwaW5nIDF0bzMgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
                "AoIBAQCybxVTY2ahevfz61NSr7Rud7Bmrim/64S25e221g2bswm3M+BTZ71urQ4s\n" +
                "JsDgpAew9ULwmJPjMBLbSqkkhld/X7p0q9ffmO10Vbgv5BzOHw71pnxP7qQlb6Tf\n" +
                "F1pDlYFDhxBYqpwxmvtgOuP5XgqlkYpCzcG0fziyhL/EmgOLR4FxaeiTejMvJEpo\n" +
                "XnN9El0THTG01qtbT6ZwLgz93yo3bxonxLRtQZtvkR6pjSJ6XF84IsUPY1CDoFdA\n" +
                "8v1Syir5cEHxYeSSkH5yJSf/KwZ+dt3NFPZDk1VAIyFqPk1UpgsG0P41UavWPetR\n" +
                "jrCB+1aydTyuHovXCrPof65cAbs9AgMBAAGjgcEwgb4wHwYDVR0jBBgwFoAU5H1f\n" +
                "0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFPz0jWEzMoB8fTWH3l9S+2nxHcES\n" +
                "MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAwGA1UdJAQFMAOAAQAw\n" +
                "JQYDVR0gBB4wHDAMBgpghkgBZQMCATABMAwGCmCGSAFlAwIBMAIwJgYDVR0hAQH/\n" +
                "BBwwGjAYBgpghkgBZQMCATABBgpghkgBZQMCATADMA0GCSqGSIb3DQEBCwUAA4IB\n" +
                "AQCQi4Yo6SjeCW1k/l7Txpz5pQjamJUDfBmgcr6v8n6RfCN+1NoMXbXX1hgti03O\n" +
                "QsU+HAnZpB1B+2GNeNdtN7a8SSutKt0+ouswvZOK3w/3rC1AxJ/MIDMk5IvjBonu\n" +
                "TBnSQIIvLIWsXcub6aEEG61GpG7cK9GnMeY4NxUH3YIIPDJs9nrrcHEaO78s+6+/\n" +
                "rlt8+XuH4h2m+xv7xB+7GN8KKKSH3gZ03X1QpayGiw91rDX52O4EhfAQcxtNfX07\n" +
                "9VvpjEcfn5Lpbe6p8BfkziM+TVf8zZmbfwR3mwinTdcLBB8AxENAbN3Oau965reL\n" +
                "23HfMPn6+Rf8SYguskWt8K0W\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIFNzCCBB+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEcMBoGA1UEAxMTUDEyIE1h\n" +
                "cHBpbmcgMXRvMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGMx\n" +
                "CzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTMw\n" +
                "MQYDVQQDEypWYWxpZCBQb2xpY3kgTWFwcGluZyBFRSBDZXJ0aWZpY2F0ZSBUZXN0\n" +
                "MTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsR+um2sZ2YQ1PJDMx\n" +
                "PRcsr0/O2t34DJXXvPuOJwddAxPoy89/ARwwYTkA9PXt9KgKpui/y4zFKMEbA+8H\n" +
                "bZLQDzwxIxLtL8sxEarXLfvaCnmRDlw/gW0onAhdfcfxfrmlX2c2IaPulEzU14xE\n" +
                "DgnBF+c2XgmRDRZcBTVrrdcHf7/pvnYU+De32CTzBJLox3TAALRveoFaHEBI79/9\n" +
                "BELaRR+ar6oiKByFa3WMM8vszIr60pC1S22V6kq9Mz1EEpZo6RyfqzzbInXQYG0f\n" +
                "6PS0sz5lDPHxBkNJh1LmIubJ5T4/Wz+eDaHkUYVtj4o8b5Jvab2kbOiy89E5slOf\n" +
                "xsGxAgMBAAGjggILMIICBzAfBgNVHSMEGDAWgBT89I1hMzKAfH01h95fUvtp8R3B\n" +
                "EjAdBgNVHQ4EFgQUH9UDtvGnSGlr19U5qGCO40QW4Q8wDgYDVR0PAQH/BAQDAgTw\n" +
                "MIIBswYDVR0gBIIBqjCCAaYwgdgGCmCGSAFlAwIBMAMwgckwgcYGCCsGAQUFBwIC\n" +
                "MIG5GoG2cTc6ICBUaGlzIGlzIHRoZSB1c2VyIG5vdGljZSBmcm9tIHF1YWxpZmll\n" +
                "ciA3IGFzc29jaWF0ZWQgd2l0aCBOSVNULXRlc3QtcG9saWN5LTMuICBUaGlzIHVz\n" +
                "ZXIgbm90aWNlIHNob3VsZCBiZSBkaXNwbGF5ZWQgd2hlbiAgTklTVC10ZXN0LXBv\n" +
                "bGljeS0xIGlzIGluIHRoZSB1c2VyLWNvbnN0cmFpbmVkLXBvbGljeS1zZXQwgcgG\n" +
                "BFUdIAAwgb8wgbwGCCsGAQUFBwICMIGvGoGscTg6ICBUaGlzIGlzIHRoZSB1c2Vy\n" +
                "IG5vdGljZSBmcm9tIHF1YWxpZmllciA4IGFzc29jaWF0ZWQgd2l0aCBhbnlQb2xp\n" +
                "Y3kuICBUaGlzIHVzZXIgbm90aWNlIHNob3VsZCBiZSBkaXNwbGF5ZWQgd2hlbiBO\n" +
                "SVNULXRlc3QtcG9saWN5LTIgaXMgaW4gdGhlIHVzZXItY29uc3RyYWluZWQtcG9s\n" +
                "aWN5LXNldDANBgkqhkiG9w0BAQsFAAOCAQEAfgUmAvc8LV3+9l0DE8PptL9L43/o\n" +
                "bdmYSWhMK8uW7yPnOAyuntZKIT/ssu9oSHFL9dBP5HAnJWslHJqimNZAGanekms0\n" +
                "uXkiqBOIEP6aMcnRKd734CgiZwnpcFzjPcVFySmBmu9/MtPOGXd4t6n8RrOewe9m\n" +
                "0HEi0c5/FzdmXz4KtIrTxRSeB1MGtle5kz9ks4Jv7YVyqg62vagxSxYIYIQahYTG\n" +
                "e3ilDUmdh9ws0RmJgp7PTQ/gV5qUwfWfv/tMWhNUyA/9bdCql87yhNTxokTdkmiZ\n" +
                "N4ZkwYg0No52Fiue+ymxwvF5R6P36fDEP0phyjh6qv6NYxsdXwd97AfS9g==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p12Mapping1to3CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        var context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), allowIncludedTrustAnchor = false, initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne)))
        var result = chain.validate(context)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        var qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        var displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        var expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid.toString() == NISTTestPolicyThree } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value


        context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), allowIncludedTrustAnchor = false, initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo)))
        result = chain.validate(context)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true
        qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid == KnownOIDs.anyPolicy } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value

    }

    "Valid Policy Mapping Test13" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnTCCAoWgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbUDFhbnlQ\n" +
                "b2xpY3kgTWFwcGluZyAxdG8yIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowYzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExMzAxBgNVBAMTKlZhbGlkIFBvbGljeSBNYXBwaW5nIEVFIENlcnRpZmlj\n" +
                "YXRlIFRlc3QxMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnps/1m\n" +
                "3VaOuWJUszOp+AmWnTRIwJe3yRXQ/ysvNkLsbmpqhnmrpxIMjmcttViCxNj6BQ8y\n" +
                "AjVAtnVSADQBiPP0ETES+3NEW8/VghqYzGJJ9H1Oxanks1Ef8mI58uQm9EWkqTJ/\n" +
                "B+UjxgqCKkHhmkikpVT/SupdPALhgRw4cta4oouQ51jqoW4rDJrRhMdlPJ5Vaiu9\n" +
                "m1N9vPK3FIKHMQGV3t1x8u/8T4xsed6ZynU+05zTwnzNl9mu3mX60lfRkLeSUeMa\n" +
                "p31xBaivLBPyEB04dzzGQaXdhBN5PaJfw98+xLjtK18L26+jqSf2BPfUVDitbCQx\n" +
                "HyLvSWWN6qntVaUCAwEAAaNrMGkwHwYDVR0jBBgwFoAUHwIoKDKOSoT4uItB8V17\n" +
                "6CVSa4YwHQYDVR0OBBYEFDxAEkPP6QrslaJxGaIDcd2mbH1QMA4GA1UdDwEB/wQE\n" +
                "AwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAIwDQYJKoZIhvcNAQELBQADggEB\n" +
                "AErtqbfufFlEyw6M9vWlfiVDCONgimPxftB15iPZe0zL/kVsUk6URd1rcQItVKBa\n" +
                "ORFqxKp+VRg3kYdzgMUeRJB242zed+QryQlZIoaLmp9JGN/rz4P1gBzIYNmTy/pw\n" +
                "kKqzkUQbzIWlf/0A1wCpI9LAxgT1TRJ5gLF8r1DrAUzB8GwH/vTzNkvPi2VFng+4\n" +
                "hXds41goc3F49m7lnsKD9bMVEKDwDugcHx3VfeTT4lICGLvILNLkp5noMxSHtnV6\n" +
                "N/mZvnAHHf3uE/PkXDibuJkm3LscaG85A0fQtiB1UYzm/IFVFW4K0NTHeS0UzyzZ\n" +
                "UHjkzxIW2sNziGzljpb8+As=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p1anyPolicyMapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        val qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        val expectedQualifier = ca.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
    }

    "Valid Policy Mapping Test14" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnTCCAoWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbUDFhbnlQ\n" +
                "b2xpY3kgTWFwcGluZyAxdG8yIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowYzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExMzAxBgNVBAMTKlZhbGlkIFBvbGljeSBNYXBwaW5nIEVFIENlcnRpZmlj\n" +
                "YXRlIFRlc3QxNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANJpXBTA\n" +
                "3EjsCM9UAoN4IpqwMwiEiVinUgeyznx8NNMjAkrsfSYyMGuchz7Ty/nobcdnUdnZ\n" +
                "50UodPrVCuy/Cyp/8vrseLEElc2iCsXifGYGSNqxw7906l2rVOvXPQocc0Oa6eTM\n" +
                "PeHQ//CnC3V209gER16XJ2u/cQshC5Hc6y8lnGf5JsMfcSuPn9QuWnsJt68YElOG\n" +
                "y9UKmK6fbYHUKH2lwKRGHvCU6UyXgTGnaf50Yu+X2RPe7F7tBWYangT+W6JsgBzu\n" +
                "SINOiTKjoAD4KysSn+jgFMcKQ6wLhFlb6myIFOX5c93qJ2z0pNCdBiKswpBwkxQ1\n" +
                "BM4Gu6OY0EE2hGkCAwEAAaNrMGkwHwYDVR0jBBgwFoAUHwIoKDKOSoT4uItB8V17\n" +
                "6CVSa4YwHQYDVR0OBBYEFP7baMrCM949EDtAPOIY3Qz4oLGuMA4GA1UdDwEB/wQE\n" +
                "AwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEB\n" +
                "AK347siub9i/zLVRrZkhB/xSOaOpN/ReyvDZsgfdj9oyMHsB1J6ToViVwrx8Af2+\n" +
                "V4a+ajppbH3FK8jq38FQiUqVwNT2N9MBUuBEBIdq74bvtj7saVjpuBWyPuxV0MMq\n" +
                "X1zLln5p7KA1M1PNT4uB+g5D1a0MP6I8oPCSiFY6s5cDyzR+vPOXvf7/RXwi8rnT\n" +
                "7hXgSU1KS5gnDt4qRS+j/eQYDQFZnkH3WIdbyupTmpFLkqAIL4FuNfBOwEJWijY4\n" +
                "lvwET2SIsHPLLgtlg6lzyY+LmlJ0ABeFLxgCjPINOKj7yafvQa2G6kaAp34XU1Ms\n" +
                "C0bZ/GDrvAwewPgQM54j7lM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p1anyPolicyMapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        val qualifiers = result.rootPolicyNode?.getAllSubtreeQualifiers()
        qualifiers?.size shouldBe 1

        val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
        val expectedQualifier = ca.findExtension<CertificatePoliciesExtension>()
            ?.certificatePolicies
            ?.first { it.oid == KnownOIDs.anyPolicy } // Verify whether the given qualifier is correctly associated with the specified policy
            ?.policyQualifiers?.first()
            ?.qualifier as Qualifier.UserNotice
        displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
    }
}