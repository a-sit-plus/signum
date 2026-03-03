package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.shouldBeInvalid
import at.asitplus.signum.supreme.shouldBeValid
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
        result.shouldBeInvalid()
        resultWithRoot.shouldBeInvalid()
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator}
        val validatorFailureWithRoot = resultWithRoot.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator}

        validatorFailure shouldNotBe null
        validatorFailureWithRoot shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "pathLenConstraint violated at cert index 4."
        validatorFailureWithRoot!!.errorMessage shouldBe "pathLenConstraint violated at cert index 4."

        val resultNotAllowed = chainWithRoot.validate(contextNotAllowedRoot)
        resultNotAllowed.shouldBeInvalid()
        resultNotAllowed.validatorFailures.firstOrNull {it.validator is BasicConstraintsValidator}!!.errorMessage shouldBe "pathLenConstraint violated at cert index 5."
    }
}