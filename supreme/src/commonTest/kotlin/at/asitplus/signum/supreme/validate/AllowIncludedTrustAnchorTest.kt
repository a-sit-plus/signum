package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.validate.BasicConstraintsValidator
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

@OptIn(ExperimentalPkiApi::class)
val AllowIncludedTrustAnchorTest by testSuite{

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
    val context = CertificateValidationContext(trustAnchors = setOf(trustAnchor) + SystemTrustStore)
    val contextNotAllowedRoot = CertificateValidationContext(trustAnchors = setOf(trustAnchor) + SystemTrustStore, allowIncludedTrustAnchor = false)


    val pathLenConstraint6CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDjTCCAnWgAwIBAgIBGzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTjELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHjAcBgNVBAMT\n" +
            "FXBhdGhMZW5Db25zdHJhaW50NiBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
            "AQoCggEBAMhrG5ilLNK2JnW0V+GiT392lCKM4vUjPjAOxrg0mdIfK2AI1D9pgYUN\n" +
            "h5jXFarP18NT65fkskd/NPPSbEePcEzi0ZjOBqnaUFS+tA425QiWkqdld/q+r4H/\n" +
            "1ZF/f6Cz6CrguSUDNPT1a0cmv1t7dlLnae1UTP9HiVBLNCTfabBaTN95vzM3dyVR\n" +
            "mcGYkT+ahiEgXDLYXuoWjqHjkz5Y8yd3+3TQ2IsyrmSN0NJCj4P/fC5sdpzFRDoB\n" +
            "FYCXsCL0gXVUsvfzn/ds1BUqxcHw6O4UUadhBj+Khuleq0forX+77bxFhUnZkGo5\n" +
            "iO+EZhvr6t32d7IG/MKfXt5nb25jypMCAwEAAaN/MH0wHwYDVR0jBBgwFoAU5H1f\n" +
            "0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFK+8ha7+TK7hjZcjiMilsWALuk7Y\n" +
            "MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwEgYDVR0T\n" +
            "AQH/BAgwBgEB/wIBBjANBgkqhkiG9w0BAQsFAAOCAQEAMJCr70MBeik9uEqE4f27\n" +
            "dR2O/kNaoqIOtzn+Y4PIzJGRspeGRjhkl4E+wafiPgHeyYCWIlO/R2E4BmI/ZNeD\n" +
            "xQCHbIVzPDHeSI7DD6F9N/atZ/b3L3J4VnfU8gFdNq1wsGqf1hxHcvdpLXLTU0LX\n" +
            "2j+th4jY/ogHv4kz3SHT7un1ktxQk2Rhb1u4PSBbQ6lI9oP4Jnda0jtakb1ZqhdZ\n" +
            "8N/sJvsfEQuqxss/jp+j70dmIGH/bDJfxU1oG0xdyi1xP2qjqdrWHI/mEVlygfXi\n" +
            "oxJ8JTfEcEHVsTffYR9fDUn0NylqCLdqFaDwLKqWl+C2inODNMpNusqleDAViw6B\n" +
            "CA==\n" +
            "-----END CERTIFICATE-----\n"

    "Valid pathLenConstraint Test13" {
        val pathLenConstraint6subCA4Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "UjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "IjAgBgNVBAMTGXBhdGhMZW5Db25zdHJhaW50NiBzdWJDQTQwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQDRaciiXPE9CRnZszi4MJScusSJJBpnJRox4Dpn\n" +
                "VJKE86q6HuEUtOzhllVlfQtaSGxhyWD8q8HpeGW7F2lqcblT0VbPyTPDF2DiPt6B\n" +
                "yGYw2J9IMmkmdJ3RiXxouq336e1FTJoPCsgwHiK1bne2i4d6L5TFen8p6IFL2XR/\n" +
                "lQyug93gOPysThsY14A2JJTNAISkJFtfEiHABPlsMtzST5OkazCJiIkGZw7+pId+\n" +
                "jkWMoOc1C4nVTUEJJbyUVYTLEetaJVxU+3tVDr1vmTHXdYu4v6rWpX3IcmEMTM9m\n" +
                "4HOqO1c92SWna0WvJLsPRm1y2/H+hhaGgvp83VrdXh/fdHrDAgMBAAGjfzB9MB8G\n" +
                "A1UdIwQYMBaAFK+8ha7+TK7hjZcjiMilsWALuk7YMB0GA1UdDgQWBBRJhdtL+xFj\n" +
                "2ZkCKLQLep4TF1oVdzAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgB\n" +
                "ZQMCATABMBIGA1UdEwEB/wQIMAYBAf8CAQQwDQYJKoZIhvcNAQELBQADggEBAJBm\n" +
                "SQWFZgiXsoHVxU/Di8Vz/JG2sTHLr58iyp38gcp+7oM/SrRqdtFe3KoaRb1LBHhK\n" +
                "Kwssx+5ukA/ZYIrKRTwv7IFUgdeQgsQDbNtAyxMkKwv2QFrtx1zaS0397wqZRGL2\n" +
                "c4ph2EI7F0IzOmzuXuj3leZTiAA1z7m+WopfmN7RxPmFT/8ZouNCUnMxryjqEzm0\n" +
                "k2vUuGzd7MLEGHlW2UVR4R/hfSOUTUBcUgC/F/aB07nCJ3Gon8ztvzRIAo7IQ1Vt\n" +
                "okYWRHbFapAq5NsEn/Z/AxDGh9kJuSIx8/mz4hcdiKvfbQTztUPBVrq1RmF++rHR\n" +
                "fwzHkZ48GGyTH5QbV8Y=\n" +
                "-----END CERTIFICATE-----\n"

        val pathLenConstraint6subsubCA41Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IHN1YkNBNDAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMFYxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMSYwJAYDVQQDEx1wYXRoTGVuQ29uc3RyYWludDYgc3Vic3ViQ0E0MTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANhwD2w1qEqflNfYtpGLRSNwCAoE\n" +
                "N7//EbgaFJKP4OGaerEZ41IHT4G8x0QOsx2RMRd6gXL9zNMmKhjoCL4Nv2mXksGt\n" +
                "crt9dSJE2MaUIQFj/cdJv+WNwoQW8amBjeMSNL7BgB8y71fnO8srWabp6vkIgDr9\n" +
                "tY0qmHZ1CLxB848d8C14NbaNGMeWJzI8ri2rXD/0sC/0LtWgg624DjmZWgxb7B8J\n" +
                "w1ERSKznjFQ4vv9imV7vJ1GZ2r5V6nBPFnmtK2r2yqAeNReHE3U2syb9lpFyOsjh\n" +
                "qTjVQdKUk5N+NAZpCipVuymCdvWcJY3C8FVmjxefqv/cJBu3Kxi7Bf6f1iMCAwEA\n" +
                "AaN/MH0wHwYDVR0jBBgwFoAUSYXbS/sRY9mZAii0C3qeExdaFXcwHQYDVR0OBBYE\n" +
                "FERapgfP9vPIx0bvZKH1W8E/grxXMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwEgYDVR0TAQH/BAgwBgEB/wIBATANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAtz+rkTNDpvnMjCDzmvVltiLfHURT3X/GipGokbedY89ANtS1dRmNFyDS\n" +
                "I1Dh17v8HsW2GR40FCIP4ImbxvPrUAQIASOVUR7iLKwSj99RwK8+Tfd9cUBx5cdA\n" +
                "nXm+KGqJ04sBKilEM6kGhA+vxZU8OJ7hck3rFVxNiIvGTZmYPlSLLQqv0X3LcWG9\n" +
                "XArnZEKfNH6Ph0LCOzlPsLI3iQ5rHluq3liWMD21LBEftUdpJ0DqzEiWEFHL8PuD\n" +
                "AtiGA+cOA0DTakpwjLnd2q1wM0S7HLVaYGSv6HErM594IUZQfWAyyyTpl3CERtH+\n" +
                "mlou5h4IgFeitqocNlVfoAX5CzZsvQ==\n" +
                "-----END CERTIFICATE-----\n"

        val pathLenConstraint6subsubsubCA41XCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpzCCAo+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEmMCQGA1UEAxMdcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IHN1YnN1YkNBNDEwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMx\n" +
                "MDgzMDAwWjBaMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0\n" +
                "ZXMgMjAxMTEqMCgGA1UEAxMhcGF0aExlbkNvbnN0cmFpbnQ2IHN1YnN1YnN1YkNB\n" +
                "NDFYMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6hM3qC08TT0qiiB1\n" +
                "AXVRGB8La1zcPFASpIZ0T1pRmbvQVay8/l8gAcVytv6KVDgpjXjXXMjjJMuAZQm6\n" +
                "ilT+eC3WrLSzBWUQDzAXTARzERVE3u4woJnBdpcyo4ZlTRGijwzYfbVlrdTNRnX1\n" +
                "ET0R9BLIK4qxRYdJvlDXoCQQFb1/58RMs9jK7lxHetuVt1ieeWF/fLRPZ2Qbf/qm\n" +
                "MpepaATXRf4Nue57jA3FyUAbvgVg2XnhRRdAEnsM90YRZHOD+XbB4Lhz2Pk6hNDM\n" +
                "xfl70rGpDXIOh9UmIYZZ2yegRx/rKDI+3wFAtcGYek4trQGg/1HoTbaKszhIgb1s\n" +
                "uJ0EUQIDAQABo3wwejAfBgNVHSMEGDAWgBREWqYHz/bzyMdG72Sh9VvBP4K8VzAd\n" +
                "BgNVHQ4EFgQUoe2i8zVUpZ+8Y+ZHalMkbEoMciwwDgYDVR0PAQH/BAQDAgEGMBcG\n" +
                "A1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n" +
                "DQEBCwUAA4IBAQBM/xztTxc6ooWAmhUfwjeTeHYxZFBCB81yMwM/agD4C3gTf+vl\n" +
                "P1CnTaXFV2aoOYDiXCkA3oL4DViFQKHcuIh6ag5pKlxB38KCH5l87W+xb4NuuyhC\n" +
                "/sYzP6PsQr43jiWtzbGRgQ8SFwN/+jX4MQnJE660ab09hgm3LmIkWCa3202nbwvR\n" +
                "rL0ILpgkzQs+IgbJY9EAE2cGiapoZ8mjKBq4EwZG6xqjqp8LO2Al8Koa1ofFwnoz\n" +
                "sYCgl+oyiP2lTkdMpg9p3gmmqWRnv0qWvfjwxnpH470rFWxL1u5nG1MM/Y2GLi5o\n" +
                "+poL/laW4KNTZOgEnijxlvBJiLfhb/mymaMZ\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpjCCAo6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEqMCgGA1UEAxMhcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IHN1YnN1YnN1YkNBNDFYMB4XDTEwMDEwMTA4MzAwMFoXDTMw\n" +
                "MTIzMTA4MzAwMFowZjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlm\n" +
                "aWNhdGVzIDIwMTExNjA0BgNVBAMTLVZhbGlkIHBhdGhMZW5Db25zdHJhaW50IEVF\n" +
                "IENlcnRpZmljYXRlIFRlc3QxMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBANGvSnWvqPuuQwnBzwyPeG9cwJSQU/bvAAFK1V8D6Yb5dGmKu++FJuY3+qmG\n" +
                "uzN3K1HFo1C/84fQ0UFNp/6H9r+9yUZ3RRSvr8A4JA0CUUv+mXfbd7+HzCqqyj0i\n" +
                "RSreaFuiXaM4QAH56nrfg31qQGb1QC14tpEXlBp8YnGh2PRbbdJQf8JbxMOlhWB9\n" +
                "A8+Dk0gwSVqUZ0nPDFy2OLQ3cEQTgjnihXBJqHztLtj4rQkwWbQCNIThrZ+XszkW\n" +
                "6rcGygZ7ZACnuuHOG5UK6qxakReo8ZuW079tnFJCPSyPk54dHLlTrsz6LyyBQBKv\n" +
                "2PzZAQcnzZWHJLoACwhOWUQ9dz8CAwEAAaNrMGkwHwYDVR0jBBgwFoAUoe2i8zVU\n" +
                "pZ+8Y+ZHalMkbEoMciwwHQYDVR0OBBYEFLdJcbHtcyweaP/yNyrJR7L7kfqpMA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcN\n" +
                "AQELBQADggEBAJTElUFCT4pcCXUHleZsjeg3hPXNJIWYLr3/MACyrDpD7M4kb1J/\n" +
                "v03VUo6r9wFgd2LE8Q9kghkRsQ1BvdGX9FijaPDMZ31kPpU1EelGutxkjU21mz6x\n" +
                "lXLb4ql8QBCLDZ+N2mEQ8y/KCYpSkKJK2X5XHQ8LRn0b/QKK64UmF4uZFxKA5Ez8\n" +
                "q1bescEhdWiAZBrFv5t+OhSHbRkRtLNB2fHkzkovVrhSgrG/qcsGInWTvF1RnV40\n" +
                "iP7VcosKbEynP8p5LQMIjt7d4f+PocFcSIVwgcVfZdwx9MS+nAj29Ynu9vQENFHI\n" +
                "xwRm/XT3hYzGswzrl5RhHyyjgAvjxwSaxfU=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint6CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(pathLenConstraint6subCA4Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(pathLenConstraint6subsubCA41Cert).getOrThrow()
        val subSubSubCa = X509Certificate.decodeFromPem(pathLenConstraint6subsubsubCA41XCert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca)
        val chainWithRoot: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRootCert)
        val result = chain.validate(context)
        val resultWithRoot = chainWithRoot.validate(context)
        result.isValid shouldBe true
        resultWithRoot.isValid shouldBe true

        chainWithRoot.validate(contextNotAllowedRoot).isValid shouldBe false
    }

    "Invalid pathLenConstraint Test11" {
        val pathLenConstraintsubCA1Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "UjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "IjAgBgNVBAMTGXBhdGhMZW5Db25zdHJhaW50NiBzdWJDQTEwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQDbl//xWkNw59SbDnUPP4oLjGtR0lPZ9ro0Y6WB\n" +
                "+VU5bQttT1STRTs4rE0dsO7uxCe4rgElYiE3RWkOX3NpjDoCjhAsZQw+qTR+RYBq\n" +
                "rXSoNY80g6yKD+hw8Og99RL00sf0/vYlP0VYG38+cMILpZerHyIjyn04miEb3KA/\n" +
                "VDh3iacw0W38bDi4vWkKM+vyzTu1bmwTK3e74GaeDQKoZFEP5dGFleHaEjf3TobK\n" +
                "mXvEVAl2OmJcm64caInLsn5ZorVxYYizcsnwtIaAVP03UFq00tHIRzthDUe/Q+qP\n" +
                "FXYesalAOV+65HnlVk3xVuhxc1/MtoUtMuaK13E0nl2h0CeBAgMBAAGjfzB9MB8G\n" +
                "A1UdIwQYMBaAFK+8ha7+TK7hjZcjiMilsWALuk7YMB0GA1UdDgQWBBQ8mpWek15W\n" +
                "YulbOJBsmjpuktv3CzAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgB\n" +
                "ZQMCATABMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAAEB\n" +
                "tPnuRM2E44XP0QrA5YQhDrvV7pzhdEmo+7ZeaAlb4I6r5jAHpCcBjuI39tihVxqF\n" +
                "ERPPrK1ZLjIt3q9ZIeih02rmWde/qqDgIGQJATl9pY2VpWX6kTu6vuZKw8eA9in2\n" +
                "PB6y5lHGnMcb8oSyvAA2gH81HxQtS0SmILOPDr8LFJ+cmw3Wv6E8T8lDYCQyb/oN\n" +
                "KCHGIY+Je3W9e+BPVyRLk9B7SbQC8dFC0zC/tkL6EImHXCP4vH5B0B2WysD7Yjav\n" +
                "6KKJgWLa7l15/ZxcxuX17E5GZG3Vl9fIZf0qfaR6nZAMXPNLOQTSR2tS8ponmk3K\n" +
                "7xxdRXaFL4msvMY7iP8=\n" +
                "-----END CERTIFICATE-----\n"

        val pathLenConstraintsubsubCA11Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IHN1YkNBMTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMFYxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMSYwJAYDVQQDEx1wYXRoTGVuQ29uc3RyYWludDYgc3Vic3ViQ0ExMTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALuN/uaJp/PshJKQyBN2TWolI/yk\n" +
                "GtUvS8cQoBUZUR7ahtG31S8sD48vf3s5ggkb3JfkLOQuwxwzfiYRZxVLxHyNbQEY\n" +
                "TUrZIoPj0+SqdDb9JCXkuCU94akI1d0xqf7M7MO0CHVZ3fcOp9qNTwm/gBdnep+x\n" +
                "pMh+g6nn73ufozCGzrnLaQp3wzWK/D4V6WjuDQMgnEjlAhxs2euUsg13HbElCSqf\n" +
                "r8Mx8bbhHdvzV5yMPVTH8mXYt/xv8YCN/ek78q+i1VI4yUw2AdB1IMwvXDnYNQJb\n" +
                "fi5ucRIthUmBwPlf7zaEHjAsNieSQL8+SdI6vOA4WUH2tNHIIvTHn5GqItECAwEA\n" +
                "AaN/MH0wHwYDVR0jBBgwFoAUPJqVnpNeVmLpWziQbJo6bpLb9wswHQYDVR0OBBYE\n" +
                "FNOmRV4CnWcWfZSAD3O5hMZbtTG+MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwEgYDVR0TAQH/BAgwBgEB/wIBATANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAT4bn1Lcr9UM45OpPECn9R4qREuYB4mAdo/NHNvnXQWoe/g3ao5y1R0OZ\n" +
                "t5aAw5Ri3ghemIraBIadgiWEpbYR1MVoR6Vx+yTLH1nq5yGKoLJ+fsEPmNwTc94O\n" +
                "Lhdu94B/gB/sy1vfq+/lnmScXMqWjE5+0kEE6BhNEJm5ep4r31/nv0oijTwLEWXn\n" +
                "VnAF/NmOWgm7+hOMVkzXTqJVY/Ep1r7QJHa65hB2+UhkzuNryOK/57CBZQbO8+qM\n" +
                "GVEymCQ858dkmH8JSpScryYdXQZb74Owx0z+zB/yiy2arubmocOwtBJIVpAv9DeV\n" +
                "HyK/COG7N0jwe98VneVl/KstdYTrDQ==\n" +
                "-----END CERTIFICATE-----\n"

        val pathLenConstraintsubsubsubCA11XCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpzCCAo+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEmMCQGA1UEAxMdcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IHN1YnN1YkNBMTEwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMx\n" +
                "MDgzMDAwWjBaMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0\n" +
                "ZXMgMjAxMTEqMCgGA1UEAxMhcGF0aExlbkNvbnN0cmFpbnQ2IHN1YnN1YnN1YkNB\n" +
                "MTFYMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzo0UoNFGT352ywLD\n" +
                "aKdwbykOrdmbb2i9KA1jFcqybAsbFggHUWmqEbSwqgepPtbWwmQBcMXHr5jGwgpl\n" +
                "WL+3XK+e37NR3CwhhHu+ab/wQ+YQhzx2X9OmDiUqEd8trpLst7xhB2MbBDmh6F8P\n" +
                "uKqc5bYgweh2rG9btTF3pNZCpAoB++xBfmWFgZ4smWnNh56Q8StmJRUbNyxSb48V\n" +
                "NT+HD0WolgMTJiGy95UzAJreX7+vD93LtqgV7qQfB5IEo7QUe0L6bKBDnl0mKubv\n" +
                "wFWMBjMBvkj8Vn+MBPpPbmt5K2xQcNNBoCCwziXkutnpt1bpOiBX3vfxaNQj5M0S\n" +
                "rkdlwQIDAQABo3wwejAfBgNVHSMEGDAWgBTTpkVeAp1nFn2UgA9zuYTGW7UxvjAd\n" +
                "BgNVHQ4EFgQUg9q4tcadyIsIfIs/7RpyJeKvG+owDgYDVR0PAQH/BAQDAgEGMBcG\n" +
                "A1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n" +
                "DQEBCwUAA4IBAQBNi63ktdmqOjJ86RiHJKt46kPz3m6rDrPF3cVUh+gYeW6bYTKa\n" +
                "2PbBbdPF90ENIZosUsg3dD1J7C+HR9oKqnG1YnghfKwhMej9z/PH+/GfepK+RADi\n" +
                "b6Op6J1+zC1JCP2oLLMPcD/KKqptle5URd4u0tWM+tKodVijSkeKq6CfHtHErBcX\n" +
                "uh0L8Q8PR3SWWmvYqfqDr0LGzl1D8hQp6EPUaQdxYFyNgiwcOz8p5pF70+ExnPMO\n" +
                "Zw7nlBHN7QqtIegieCdwl/DJQCtfvxXYVGs2CW4af9p0ttM5lIDNXuoMRUd1rWTR\n" +
                "vE63/I9pL52qh/9aX8GhBGuj4kP4E8OxgFo6\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqDCCApCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEqMCgGA1UEAxMhcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IHN1YnN1YnN1YkNBMTFYMB4XDTEwMDEwMTA4MzAwMFoXDTMw\n" +
                "MTIzMTA4MzAwMFowaDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlm\n" +
                "aWNhdGVzIDIwMTExODA2BgNVBAMTL0ludmFsaWQgcGF0aExlbkNvbnN0cmFpbnQg\n" +
                "RUUgQ2VydGlmaWNhdGUgVGVzdDExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
                "CgKCAQEA1cl8/9ip/J/At2SsSX+IJEEVyheRfuATAjbGXo7Cxrc0hDSRHTovhpBn\n" +
                "9bvr2U3tLle6PnM+04bGz+Xt4+XAwq3bYepL0Y9TKx6S9sFwdVSWM3tpfS15OfeB\n" +
                "G0dIugOZMSm+o8VQUoFRkEazcWCOUdu+9KEHXBecAeWxRof3IM0R6i3cTprfjCs5\n" +
                "yXgsCln5HUPLDw5twRYOEE5mnEWtraWEFUeYE8xVFwwk69N9b95gpTsEvzPnyc7Y\n" +
                "vcEeVGDsezBQmPxDSOXA1pDOqBswDj90rFy/ZxQWPSOdV7dSk08Aa2KayXgL30gz\n" +
                "mO6ENzNWfIZ0g6TN9Oq8K+lhRx/E6wIDAQABo2swaTAfBgNVHSMEGDAWgBSD2ri1\n" +
                "xp3Iiwh8iz/tGnIl4q8b6jAdBgNVHQ4EFgQUOVf5EG2PkPu3WYGjOi+xdDjbuacw\n" +
                "DgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG\n" +
                "9w0BAQsFAAOCAQEApEdV59RrhEgGjn1V6YgmOZrmFoy7Vr1Ss36w+MY7OqJ5zdYj\n" +
                "BJPk/cDWct/Fk/X+i735WzzY11K4KrLc1DVkfrTyRPLHChRFma5g0p5OUUDvofyj\n" +
                "5gky5i8S3+3l8GthFqJyVgjqagILlj6+az/liTiCLrlKk3+MOeI3xZfqu0fhfWTL\n" +
                "CMmxAhrG5hjMR/YAcoSLsM3Vu7cwWVn8zB7PA22EnEBspIxwjrH1diVSSix0Mr2U\n" +
                "VIjrBMmLHIuYv2s4ZS29iPsKcikiXK6+GynT6QuNf0hXEB9a/H1NEBu69+AnXnNN\n" +
                "8KDP6+hPJxVKCLApWqbmGqJE8b6swlhRomACaA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint6CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(pathLenConstraintsubCA1Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(pathLenConstraintsubsubCA11Cert).getOrThrow()
        val subSubSubCa = X509Certificate.decodeFromPem(pathLenConstraintsubsubsubCA11XCert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca)
        val chainWithRoot: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRootCert)
        val result = chain.validate(context)
        val resultWithRoot = chainWithRoot.validate(context)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator}
        val validatorFailureWithRoot = resultWithRoot.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator}

        validatorFailure shouldNotBe null
        validatorFailureWithRoot shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "pathLenConstraint violated at cert index 4."
        validatorFailureWithRoot!!.errorMessage shouldBe "pathLenConstraint violated at cert index 4."

        val resultNotAllowed = chainWithRoot.validate(contextNotAllowedRoot)
        resultNotAllowed.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator}!!.errorMessage shouldBe "pathLenConstraint violated at cert index 5."
    }

    "Valid DN nameConstraints Test1" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDuDCCAqCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGCMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTExNjA0BgNVBAMTLVZhbGlkIERO\n" +
                "IG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAMRVH83Hm46JPU28u6W/BR3a95naRI7hTLko\n" +
                "SOFjXkkjx8tjModC1M4QxWpoMZj2AF0Fd4Aykw75HS8W37wb8UjFS3SrXQ66qVwY\n" +
                "h0CDz8mNOvtGSanquco3tZeMqoDe8/EXhotzwnf5F83cyp7XB7OiEQPzbplkD4jQ\n" +
                "GZ5d/SF0lBUdhxilqRlXSemd1kfGop73BOGmgqkQhP+I+4ZZVwxUO5pXGzRpfGK+\n" +
                "h8ZiOM/JAxpmhdaU1HC6Zf4YDqA2XpKZKQ232myfX4SObpXZ0DUOLNNDzYisj14W\n" +
                "3ygeNgyIUFVp8hLPI6/BXTJqziW0TqoqCb5Joq+32zjYPwJNxcECAwEAAaNrMGkw\n" +
                "HwYDVR0jBBgwFoAUQXhCRs1OqILn4Tnf96kWwAr874YwHQYDVR0OBBYEFF3+CfUG\n" +
                "qPKNIJRROjk0yUUKmZ2SMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCG\n" +
                "SAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAEzeTUMhQZChACqQef2LLNvj+BfT\n" +
                "VkDB0FVyPo3Yti8bRH8ZnItB8CWkS1iBvv4Bwgp7S8MpAGrgmyBCAO93VjySw5a2\n" +
                "kEU/55B39tPKMQqWOAvi7DU31mWdWemMwD3u/SuK/8pnPOANjduViBKze8rUj4u0\n" +
                "tbaYLor/qh4Lxgux9Xw1K+rwKlV9xDvoRLqNMsSReCLfMjMwXkUV7CL/6XjOGACM\n" +
                "XMPQkJx1SnWLerNLLi2dzO1Ly9Ikr4jTEflJ/lxdw8Fa88eLXNte+JH0OcwwwLQM\n" +
                "PiSkYK4B8y0A3Psl9309+kocX+YG1ppMoXg64Nt3YQ6kZqw/07gDFODEz3M=\n" +
                "-----END CERTIFICATE-----"

        val nameConstraintsDN1CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIID7TCCAtWgAwIBAgIBPjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHzAdBgNVBAMT\n" +
                "Fm5hbWVDb25zdHJhaW50cyBETjEgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
                "ggEKAoIBAQDIFZChS4W10eHwp3smMrXyTluiMJTrq0f8LEx4D63qlvrjNngGxCHt\n" +
                "BOlFbIH3uKwK24yKHywpFK38bHLyDf+2LoaEYox32sfyeqneYurTGJ4sZ1T/fsZk\n" +
                "lG/n5fkMlvIU0iu4eOkshyEEtvUGpvdSEg4a7TiadjmsAZkJkgBHV0h9VYaRYvgY\n" +
                "BnDsTd8MrzKo0bNnpMgiUGtGJB9lB0DmhO51IelaxiyaJUVIsKUZfpA1NPjSboLi\n" +
                "NLgKhP8El/AlBY3BG190xJ3a5xDIhDq5SRTJ16554PIIwzfE7nvY+9TpwfkYvVKL\n" +
                "zCOTyrA6VnFwTLKc8sLYKFfmKNEboLafAgMBAAGjgd0wgdowHwYDVR0jBBgwFoAU\n" +
                "5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFEF4QkbNTqiC5+E53/epFsAK\n" +
                "/O+GMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYD\n" +
                "VR0TAQH/BAUwAwEB/zBeBgNVHR4BAf8EVDBSoFAwTqRMMEoxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJt\n" +
                "aXR0ZWRTdWJ0cmVlMTANBgkqhkiG9w0BAQsFAAOCAQEAaRFMK70B7a7bqMhucX7K\n" +
                "3AnChP1D8T/CFQUnOWeC/yKAcHbplQf3uWzL52ZJIoKLJaT7dnCuLxx9St/m5aCI\n" +
                "MKZuIda+85I2WisV4brJJWyZlgLauA0WLZuEswqB0viCZG0vgtWTm9uN6O8Lqua3\n" +
                "fnM/0WQtcmMMNs3NWN+FTX6SHIu5Z/DuUZWSF0H76jjheSJG2wXn0TJk8RRJ7mn5\n" +
                "dnDEoDFUpePO0qaOjl1KGov28zz2QGIr7Nq+S0Z3Gk1Z2O3DlgYMeYtqkiMPKZ4Y\n" +
                "sPDZIABuaSYI1o0ZoFnpLgiWVWbBJDO3w5x6eIS/CueS8hKfX0h7+dIcgQhABleo\n" +
                "2w==\n" +
                "-----END CERTIFICATE-----\n"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain = listOf(leaf, ca)
        val chainWithRoot = listOf(leaf, ca, trustAnchorRootCert)

        val result = chain.validate(context)
        val resultWithRoot = chainWithRoot.validate(context)
        result.isValid shouldBe true
        resultWithRoot.isValid shouldBe true

        // Since root is not omitted from the chain, it will expect it to have
        val r = chainWithRoot.validate(contextNotAllowedRoot)
        r.isValid shouldBe false
    }

}