package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.Qualifier
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodeCertificatePolicies
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodePolicyConstraints
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

open class PkiExtensionsDecodingTest : FreeSpec({

    "User Notice Decoding" {
        val certUserNoticeQualifierPem = "-----BEGIN CERTIFICATE-----\n" +
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

        val cert = X509Certificate.decodeFromPem(certUserNoticeQualifierPem).getOrThrow()
        val policyInfo = cert.findExtension(KnownOIDs.certificatePolicies_2_5_29_32)?.decodeCertificatePolicies()?.get(0)

        policyInfo?.policyQualifiers?.shouldHaveSize(1)

        val userNotice = policyInfo?.policyQualifiers?.first()?.qualifier.shouldBeInstanceOf<Qualifier.UserNotice>()

        userNotice.explicitText?.value shouldBe "q1:  This is the user notice from qualifier 1.  This certificate is for test purposes only"
    }

    "CPS Pointer Decoding" {
        val certCPSQualifierPem = "-----BEGIN CERTIFICATE-----\n" +
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

        val cert = X509Certificate.decodeFromPem(certCPSQualifierPem).getOrThrow()
        val policyInfo = cert.findExtension(KnownOIDs.certificatePolicies_2_5_29_32)?.decodeCertificatePolicies()?.get(0)

        policyInfo?.policyQualifiers?.shouldHaveSize(1)

        val cpsUri = policyInfo?.policyQualifiers?.first()?.qualifier.shouldBeInstanceOf<Qualifier.CPSUri>()

        cpsUri.uri.value shouldBe "http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/pki_registration.html#PKITest"
    }

})
