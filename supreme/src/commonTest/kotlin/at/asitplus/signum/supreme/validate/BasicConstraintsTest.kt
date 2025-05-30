package at.asitplus.signum.supreme.validate

import at.asitplus.signum.BasicConstraintsException
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

/*
* PKITS 4.6 Verifying Basic Constraints
* */
open class BasicConstraintsTest : FreeSpec({

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
    val trustAnchorRoot = X509Certificate.decodeFromPem(trustAnchorRootCertificate).getOrThrow()

    val pathLenConstraint0CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDjTCCAnWgAwIBAgIBGjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTjELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHjAcBgNVBAMT\n" +
            "FXBhdGhMZW5Db25zdHJhaW50MCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
            "AQoCggEBAMi803q1skF3rlRLLe9UJy2uHFEYjwqmpOnvDT+3GAFrYFYjS4u7307M\n" +
            "pOxI7vPwlpRMURsQY4k8IGlNmXgHJLTphFdARhmPWskpfAfC/7mnNrYqvOCixnG4\n" +
            "1EYhnCrKN7Uhni/l6AHT0cLp3HmnNXFq0YSWVpWOZ5yx7KpUld75+MqUQixEieXc\n" +
            "PunjGC6MjHJQFrko5igrcGu/PcETu9ao2CQZdqnYb17ftxSiSPRUtwilTLEikINo\n" +
            "tzklWM6HEO+aQyXi+Ib5UVfmYuUYZCEA5xZk5c1Q8oYd3EAvbP2EHQL1cPo+etR8\n" +
            "K5IZ3zpu7rt1sD8Lw4JSFVNejDoZrl0CAwEAAaN/MH0wHwYDVR0jBBgwFoAU5H1f\n" +
            "0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFJsrsko8kMVuUAHJIr1jzgnxjD36\n" +
            "MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwEgYDVR0T\n" +
            "AQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAQMor5mePNE4lGLLT0vop\n" +
            "fvEOCEJSav9+ufqqnH7BrMWQ7QzXH1pHdA/IgPAXXTRVWv2U83srUxERw6aAyuSW\n" +
            "DJ2g9iW1ti3fqLM0X+jDLrCkjIpyeG+9R+uvEG48FTVEYrWr0yeI73K235XmZh+0\n" +
            "vht6STnnrNNX+ZUS12wEPOes/TskflyZXcOcodC97gr+veazS8ghL5RPXKyIkBLn\n" +
            "jRsarcwDyN8KQbSlsUtvv9nowqVzptishiTXHZRnKMWMr91gqVnRkhjoXPsRGsq1\n" +
            "ytueK4tqUCRnBwrBp+nfg3UyWHfh+Nj6XG+VYkjAXUVytqZdX2rMFTh7qwGMH/zz\n" +
            "jA==\n" +
            "-----END CERTIFICATE-----\n"
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
    val pathLenConstraint0SelfIssuedCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDkzCCAnugAwIBAgIBBDANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
            "bkNvbnN0cmFpbnQwIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
            "TjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
            "HjAcBgNVBAMTFXBhdGhMZW5Db25zdHJhaW50MCBDQTCCASIwDQYJKoZIhvcNAQEB\n" +
            "BQADggEPADCCAQoCggEBAK6/MMP+APou9dhuFL2cxOt7900Egk7KHnsv5qHiDiRd\n" +
            "yxJk39iF3O2SK7dy1ChKhZtlI7sMznTFD6NrnR9/wAdj8sabFleXM7RMXGCNbKD9\n" +
            "q0fDqn2pTxJ7oCk7BLjcdvR/coWmAWZo+oC6F/cdZuHAvNI5HILlOF/EbAw1UeNo\n" +
            "XXfeay8Mjf54mnKGbZLeAMqwpy1Dq0KwnLhMpd54eAPaWeipqPhlAQ/Uc43sVlLK\n" +
            "xAR+DD1dGh64vr84GTqtF5vWJ2vW3dC8bMiXqVsOyXHJQyFRNBO1f4QedlYiBby+\n" +
            "MpxTjvjnRZle19hecvhW3ZxBKspQoOc2NveKAdKEPNkCAwEAAaN8MHowHwYDVR0j\n" +
            "BBgwFoAUmyuySjyQxW5QAckivWPOCfGMPfowHQYDVR0OBBYEFIDrc75NmZ6UvRdL\n" +
            "WvfPV3d0w193MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIB\n" +
            "MAEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFT0uTP1wQtXV\n" +
            "2vfQ7uNjYgTZOtIy6yAKUZKbDssGtwZodj4sAMOqIK4Cc0unzCifaPFPfPS1qDUW\n" +
            "d7PGUrKDp81rISzOr2XqNZGaMXrdskfDzghTXdwPfpFtxmEPg+ewamuI8zcRTfOj\n" +
            "sxUB/afnqSBUqkRu5BB7iBE6Vd8Ig97SScxXpudBB/jsm2zf9Hhr4U+cUUQGJpUM\n" +
            "tVi+MpRRhF5F5Ak9gf/FG6u9D5tawpY7y8nekPGbJqpFV0xJnCp/C0qaJbbTwU/L\n" +
            "lL5QLVBpLCfdEevwI/CTEUXmLJC46mLDhN3mcCBK0fL1Vjj3k9NRpS67i3/m9ZzT\n" +
            "ggRxSu4nuA==\n" +
            "-----END CERTIFICATE-----\n"


    "Invalid Missing basicConstraints Test1" {
        val missingBasicConstraintsCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDfzCCAmegAwIBAgIBFjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowVDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExJDAiBgNVBAMT\n" +
                "G01pc3NpbmcgYmFzaWNDb25zdHJhaW50cyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
                "ggEPADCCAQoCggEBALRWdlqDlLWqsR0om+sJgmRxE4QNnMkpzFQdkA65CXM2PzK9\n" +
                "+8cj6UqaHsEvMktB77yHztk2GhmEkrd/i6EAJNjxwBjAq1X0OhcFG4e0llZk1JaH\n" +
                "50eCwZJ0OG92PZYAQ2l0d99/SvUTSEpZ6v/PmXDIiSS3vtGN+Kfbpw4S+3DMTduC\n" +
                "vBjx6ibgsBYd68b4Oo0T+gYkKx2v+UZ8n8cV5WjVP0/Uy4tiQIU4MXUeNjZ4UKat\n" +
                "zRadXVq5mGEK4tmP7RGn+5J+vukGq5TB/hg1+PvzY0QQ6TOLruuLhtGEwbTDZkz1\n" +
                "uwiUqE7C4NALqABdICfwJonm3gjliEENTC8L9zMCAwEAAaNrMGkwHwYDVR0jBBgw\n" +
                "FoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFDBWvBURjU/GJsa1nKFw\n" +
                "ktL5Tw15MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAOBgNVHQ8BAf8EBAMCAQYw\n" +
                "DQYJKoZIhvcNAQELBQADggEBAFgnHD7Mz1Gz+3SEuPsr7PgtjvAo5hnRZHgvlAAE\n" +
                "X+usbcykRvVsgwp+d2SZPgybcYQ6g1CwGtNS9/dEHvoLXe37lkBr3kmE2/kEdjZi\n" +
                "IHEU1Oh9thXs0X+Eg9m3JJ8ZI0iLuWpQd7xHA+riTlJ46SLE1d1xGHPSwAxRi3fk\n" +
                "US7X8DAxejxjGixWGF988Ib3NqMMwx2Jcs5pf3u8kUiulP/kyK/+jtiDfCIxIJLw\n" +
                "IaoFs5osPraKaE5IvvDrSvM0k5yBs+9ZU2WMNoMSzzY3+jy5+OETQPszItgXQ40W\n" +
                "Jt2Cxs8ZzBFnuym9UsD9m6IXe38eiJOoP2ruwmFn6uaNPak=\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqDCCApCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbTWlzc2lu\n" +
                "ZyBiYXNpY0NvbnN0cmFpbnRzIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowbjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExPjA8BgNVBAMTNUludmFsaWQgTWlzc2luZyBiYXNpY0NvbnN0cmFpbnRz\n" +
                "IEVFIENlcnRpZmljYXRlIFRlc3QxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
                "CgKCAQEAz0Q7jVXn/KP1L4kWn3MnNkLMHv4kNcWGV8Sz2Z2VUq8WlLhFuzpFvyPh\n" +
                "NXcaZ98iVRqDqvSmb25/Gf5HoyrLTFxayY0wm72Drm5VW6REQ9evIg3xJV2x/4pg\n" +
                "7qHE1ikSCD1yHSgrhQvWVVbkYnnTSgVERxm81TDFMmn6nOQzuvjLr50dgcdz9tI1\n" +
                "sULjP7pyk7vDuBRNhsphW+QP7iUDr02Fph7IO2nJevAZ1p+80O4lMoLLAWelO7c5\n" +
                "KKyhGa2NqZOCqSsS+cUMtkhUGhEyDdlxC1maCPpsS6zfmtWasUKBn1FLLGXDzALC\n" +
                "COWJwxztub3n2UVKu2bFEn6aYK9iFQIDAQABo2swaTAfBgNVHSMEGDAWgBQwVrwV\n" +
                "EY1PxibGtZyhcJLS+U8NeTAdBgNVHQ4EFgQUTfAA8MgHRVCO/ShtbVSoByR2AIQw\n" +
                "DgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG\n" +
                "9w0BAQsFAAOCAQEAVnYgcBUarDoQoiuDXLPNBtPKARX91BCSAJSI4s0yP8Ba307d\n" +
                "28L6BUVWzbYevwBKK1042PTO3Baz5WTc8I/cgNMUolZKfSbjrTCZ5H3MLVpH1Zdj\n" +
                "zr7Y4bNppL3aGwXPjjaDHHE6F3h4ukFZaoX9fTr1OTxcyOmz96/hLJ3NbHmRPHPv\n" +
                "pA1y5yepi3RDltyIMQsXIGPIofZ19LQ/+hCjYuh01wrd2r4DEQYDmyEEDMXRaeFy\n" +
                "LSZqGQBhvOwcrfX6iz2cIz8YnbfU/cte5C2Id7V7zW5GZP4oCgjHsANbe+hGVbsR\n" +
                "AUSJ4G96MY5zlwVFYdpLldKm2BywOGs+CU+uxQ==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(missingBasicConstraintsCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca, trustAnchorRoot)

        shouldThrow<BasicConstraintsException> { chain.validate() }.apply {
            message shouldBe "Missing basicConstraints extension at cert index 1."
        }
    }

    "Invalid cA False Test2" {
        val basicConstraintsCriticalFalseCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlzCCAn+gAwIBAgIBFzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowXjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExLjAsBgNVBAMT\n" +
                "JWJhc2ljQ29uc3RyYWludHMgQ3JpdGljYWwgY0EgRmFsc2UgQ0EwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK0TuX7lUycbAgxfZnKcg+Rx2r61nSTPYw\n" +
                "1lgfYLDJALaWLUioE7qIrkbpO713AYSExS2mbm+lahJiFznGgpZreL+cY6se844t\n" +
                "2TG9ZU7Z/gap/UCKGu/Zllq30Mx5nuX2yQJbH9oLp8aaxIFJrE1l2bzw5oJNITf3\n" +
                "h5D0ZE1s4j/cvDQ1AeIn56HSsU+FFJ+WZ9tlpOG5C8WbaRUJBDg68FEStgq63Dtd\n" +
                "7zje4jykLw9FE6ecksEZ87TeoOVbxsM68jr03/wByZKDkiwM4LGgHHFyfQRgHWbd\n" +
                "kMpTDhyrk0CNv7F3kQ2LOfbZP3Xt2KTXYoORYMC/kSf+rfKaAORnAgMBAAGjeTB3\n" +
                "MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBRw30Qv\n" +
                "A5kcF3MY8jY8FDTQCdHy7TAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAEvnbglu\n" +
                "cVBQ9vbuv8jUUzxvxBLqBbvwfsY6QmZGVgNKQOIkARLkguDt6PpVuB/w2uRFBRFv\n" +
                "zcV1ooleAKis9t42aNamzgdDLxSQ060Z98yGeU33La7uqRX6PVzvYncwVKOPl1mu\n" +
                "Hr9CEPc9EHYJF9mWYGGYXhNkrvlFpow1Jgg6zWtmWtoYfl27XoGBnuLGPqmd9Qn8\n" +
                "aDWfNe4k8XgVwemq+n+r/tYGXW8P91DXk/YZCFS4x8hbx+0VvCcOXWZ2ApWGkX8j\n" +
                "KHGzhl3jFqhQOSy66QljjW1qVxPjkL33l2TaGrOQXv/Ykf6r2K2bCxKGvahSAH1A\n" +
                "tA53saU+pZ94JrU=\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBeMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEuMCwGA1UEAxMlYmFzaWND\n" +
                "b25zdHJhaW50cyBDcml0aWNhbCBjQSBGYWxzZSBDQTAeFw0xMDAxMDEwODMwMDBa\n" +
                "Fw0zMDEyMzEwODMwMDBaMF4xCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENl\n" +
                "cnRpZmljYXRlcyAyMDExMS4wLAYDVQQDEyVJbnZhbGlkIGNBIEZhbHNlIEVFIENl\n" +
                "cnRpZmljYXRlIFRlc3QyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n" +
                "5pPuSskaT7pQvNS0XtLWfsJa8Jtq4V2jt2MY0BMegVCjknFfUEajR7X40eKlCACB\n" +
                "QD9awY8FrNrkR+k6IHrtNsn7YhwyO7gxC+8loRip9NEnrKweYDB1MiYGEhmep3wu\n" +
                "IXUrFdNVIXbazuQDQzTNVRnJGGSKxP8SlxIrLg6C7gxmYpr61WlajauE87FtalMe\n" +
                "lAMQp3pJUiwF8Ooy36Ja/38fgyVhEX/0Qw+OcMfAg4Oe8xVhLaffWF8ZBpji/z45\n" +
                "NqiNJ/ZJ+IqwfcAp+8vhcM26GBX4l0c7CBXfjSCi2NvUdsHjv2XeloDRDdfZfoBx\n" +
                "lGdkeODccKklxTJE72ylVwIDAQABo2swaTAfBgNVHSMEGDAWgBRw30QvA5kcF3MY\n" +
                "8jY8FDTQCdHy7TAdBgNVHQ4EFgQUfLh7mOwGIojKj5FQ2sTCLnyBGFIwDgYDVR0P\n" +
                "AQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAYrhQ0Oit0VO721Zoeuz9vRSVb5pEyWOkXstseN4oBBCAwd+L63rzNYGT\n" +
                "SIzFTMh7ePO160xVWOJnSjbCDhEDdLG48yYI1bIZ5B7mdOaGqfo+kh3+oWXbM8CE\n" +
                "+hQu0PbS2d931zpzKgikars+50o3g8veVaD59Wxft/JGeiIIK1Hld97vjNRnsi2o\n" +
                "7wqeYVTQHeRT4kksFTPfY0O2DgeGDVvCwIPP11DtSxkgBkonxBqCSUIqngKdDPV9\n" +
                "nD1PbNFiabVgIB1AWLThO0zAge4ZjiHSzaY6lZwCzqW7KWLgjscmvHDd2Y2DTIR3\n" +
                "xE8o44JWsXaJAO5uYDD8w0iQQ2Zagw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(basicConstraintsCriticalFalseCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca, trustAnchorRoot)

        shouldThrow<BasicConstraintsException> { chain.validate() }.apply {
            message shouldBe "Missing CA flag at cert index 1."
        }
    }

    "Invalid cA False Test3" {
        val basicConstraintsNotCriticalcAFalseCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmDCCAoCgAwIBAgIBGDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowYjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExMjAwBgNVBAMT\n" +
                "KWJhc2ljQ29uc3RyYWludHMgTm90IENyaXRpY2FsIGNBIEZhbHNlIENBMIIBIjAN\n" +
                "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn0EwqHs6AKdSF6fQyFQ9KzZMLoAg\n" +
                "o3Vjz4MudMtI8xe5SGdgQiGK1w7acKOWzVg/xRG+7Lv8osjGB9+m6MsYgXACOVt+\n" +
                "2VSmsuHQ5F9UZIoaXfsCFV8J4KJYuqWYJt84PIzUoIEKHHloghRQvI4qv8SPJUSI\n" +
                "LbaeRckJAzsLhRVOTGIOCPTtj/rosKpdBdHofuzdtVkSJvMu3NcN1oL6haAaDtS+\n" +
                "MYAizyLnTbNYBS/NW+6hImyNLYvmXYCh4rVq0PTTEJvm9b7SQHyHyFroN3a9vxof\n" +
                "2+bQq6Lpim0QBKi4rBRDeJn+zc5EZnBkEDtZXEQ808JddIboTOi4JDkKbwIDAQAB\n" +
                "o3YwdDAfBgNVHSMEGDAWgBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQU\n" +
                "OdCbt08pN77TsIp26mqeze9GvlgwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4w\n" +
                "DAYKYIZIAWUDAgEwATAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQB1uT+Y\n" +
                "KoMDcmuoxjk4KoBNTWPmR8eXegKa3WfyOJxYRTqlDhmDd/N+3Ifk/QzDqXitKUEI\n" +
                "BWL13NTh6ngG9AIBrRGpk5XmixKTxCP5FxGjsd5dM/So079U0+K9s90xzwOwolJi\n" +
                "4Fkih0eeRu2ntqwCvLsIEOSJMH7uSOISuRjYqMAnzlP4FFXYeLOGQLtUFln/lseC\n" +
                "KfD0roxZZ7W8KVWLICwGAFrw5rBnZuyoNIcCJUtH9uJ4ugid0BmYrICWLFwEU3af\n" +
                "W7GJZmRfegol/5TJy14XSb6vxyp2kAPmgdDZTmLiB36xaixjsS/7AIhejzDJ3gHU\n" +
                "SIxm4tAlyWAjCBXh\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpjCCAo6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEyMDAGA1UEAxMpYmFzaWND\n" +
                "b25zdHJhaW50cyBOb3QgQ3JpdGljYWwgY0EgRmFsc2UgQ0EwHhcNMTAwMTAxMDgz\n" +
                "MDAwWhcNMzAxMjMxMDgzMDAwWjBeMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVz\n" +
                "dCBDZXJ0aWZpY2F0ZXMgMjAxMTEuMCwGA1UEAxMlSW52YWxpZCBjQSBGYWxzZSBF\n" +
                "RSBDZXJ0aWZpY2F0ZSBUZXN0MzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBAOMqfzk11boRFBbpNA1tq4GZJbk1M45bsflY/IBB0d8KUdhotWgSOm065GL3\n" +
                "sB10F5JZI/sLVpXuH7R9TABBvnZu8XqX5RKKkNB7zMXlkpr4TFXGZnYgSmX09ta+\n" +
                "fuZ4TQgj6BdztW1l/634f4exa7qZirzCISqddB99CN318WhQgMqxmounqUfkUD12\n" +
                "e1UM3TjOPKqI7eYOJIfnfw2Ea6BhT55ncTXp5lcAhAajos+iWYhiqlPWc+cd1c8U\n" +
                "3VrVi7kuKK6uuVBqA68QTiDnuaPEJsxadp9AuYY5WYGT4HT2HpsXzCd6R2fk94hZ\n" +
                "iV/C0hSIAq0mVtq9FJF9qh/XwsECAwEAAaNrMGkwHwYDVR0jBBgwFoAUOdCbt08p\n" +
                "N77TsIp26mqeze9GvlgwHQYDVR0OBBYEFI/4W2j9iCltyb9KCY6b8q11whJ3MA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcN\n" +
                "AQELBQADggEBAG22QQs5JmmHtqLDRPAiJP+IjtpGyiOCH7IhyGLW6MKk88cjH9xe\n" +
                "M066O9SE3asTYTrhQBirfy+nOxV1Qg+DdSmtA6ibr3USxTkH5xcz3OR+Sd3fkxEI\n" +
                "qkjK5nYkXWs6B/xbX8A3iUrRmG2Yp/gLI4Fs3ZEobwh93E7wIamQ8PJ1SbnXTTcx\n" +
                "xBy/IKY/usd7NdwtobmHP6fH2bWM0GyNxmOscLCxAhESLjmuq30srVG/jHs/Q0vL\n" +
                "Jww3lWZSPbJXcRxKMzlu35IrP92RZWjtByv1Wndugh7q5rjT1ccw0eF95b/U5whx\n" +
                "X2XPc74bSpqoh8dfNGTWjtq2JeHhGoJd+9k=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(basicConstraintsNotCriticalcAFalseCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca, trustAnchorRoot)

        shouldThrow<BasicConstraintsException> { chain.validate() }.apply {
            message shouldBe "basicConstraints extension must be critical (index 1)."
        }
    }

    "Invalid pathLenConstraint Test5" {
        val pathLenConstraint0subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDljCCAn6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQwIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "UTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "ITAfBgNVBAMTGHBhdGhMZW5Db25zdHJhaW50MCBzdWJDQTCCASIwDQYJKoZIhvcN\n" +
                "AQEBBQADggEPADCCAQoCggEBAK30/E10HSTUTxTe/EMYjXq+P+oyGA3ZxAEz6OhM\n" +
                "uPKZnp0OGu7/kIPVhWkfbEa9J4wKrbbMmk3gqx/fvbo6/ZhWDkFq/fjLvjkCC8F7\n" +
                "CFwXrLxGAoGd4EvdGIUyZ5zUeIRZYWYjlC8J32dDAQvbGx9/8j9lOG/3Vm0cHXz7\n" +
                "kF6B9mHp7OHEm4URyAKM1Bn2QCbsRCqkOFxWLh6XbREdKFYWFRExN9dL9rwOZ3u1\n" +
                "psGCpvAjXq9dw7vvmrSqJAPku2N+qx9NUysonIUNKLf3q3ynLLK91S5C8KeXoGWS\n" +
                "ujGRF1gnvTNlPcEf8ESRg53XokYZ7FIrxPCmhtNwnAAV0a0CAwEAAaN8MHowHwYD\n" +
                "VR0jBBgwFoAUmyuySjyQxW5QAckivWPOCfGMPfowHQYDVR0OBBYEFBRiZxB90jfF\n" +
                "cgbQ3n+1Fh3Ko3NeMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFl\n" +
                "AwIBMAEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEALpjmzN+R\n" +
                "TIzv5jQAMokgflELINf1b8eTeG3Fz9CvOZ68dGJIMr0Qigr2epEQ4/KW9mHXUgGn\n" +
                "8GwXvnraoLiq6/LyFEW6PE9yl4lpotlxLmMnoEDDno5rfLWgKC2uygKXJrwCMAxE\n" +
                "6pNO66V6Qi4nWwXpHBwnbeAVp137LuKp+Fw+SwmcqSFFIScifwSCS5kFokqPUM9l\n" +
                "sYJZg2bUDj8cMGKYx/erl/LEZOT56lIcZBg0v5ablxB8XrDA1nx3QDONqd6qBjzU\n" +
                "FFUqgJpu2CwiZLZ77VRfjuF889mp8SHnwi5tPglVZFBJ4t+72LfjXgM32a7rCwrE\n" +
                "O1uFD6QiGDQAQw==\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnjCCAoagAwIBAgIBATANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYcGF0aExl\n" +
                "bkNvbnN0cmFpbnQwIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowZzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExNzA1BgNVBAMTLkludmFsaWQgcGF0aExlbkNvbnN0cmFpbnQgRUUgQ2VydGlm\n" +
                "aWNhdGUgVGVzdDUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPgxp+\n" +
                "Hpglfzp9XX1K1glTgljSpG1M9dGpAlVk7K39GMVwkmnAtSBhQVBdG8GDNnr3kqCC\n" +
                "J7LPOrNTDcRRkO4T7xdBL1RqmzOAuHHgJCiFt51qziQe//kZcmyIOwY8pgHN4Cy1\n" +
                "q0BeWybbU4B9ybMiIVzFImOoOPUzkaADKic1iW1OBj5NpGCZ91qFyZx0Itk/iBC3\n" +
                "v7CN2B8Qaho3hypDTCSRmVHiBB1kD/AKFU8UohIiHXsyGxbCg1bBLuKmWRTZ43y7\n" +
                "L1m4qHBOg2i3do13YLss2oZoknsoOHOBa0YLrFXPPMQTNrOU6Im4IYiUU+Ge7+1g\n" +
                "2a05ooIRBTS+QhSTAgMBAAGjazBpMB8GA1UdIwQYMBaAFBRiZxB90jfFcgbQ3n+1\n" +
                "Fh3Ko3NeMB0GA1UdDgQWBBQPpyPBesQ9pYPwqgwp6+Jq4890gDAOBgNVHQ8BAf8E\n" +
                "BAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IB\n" +
                "AQB/58kEOCkIVV2FaRCkyOKRYGVC3KnDEBQjc6w3ZEm+f3vFHJyB8V63J+zf9MBi\n" +
                "i2LvwwRTaUusfrrVteAcCYcoXOSHmRo82sY4vWJ0KBn0CDHuQw/WakD12geNfcjn\n" +
                "yTu2LTe+0as0RhQ91krC5qJuzoN4FBVj8eKhVoD9YQFCzoD+Rq7WqabgUVVjowvL\n" +
                "UzSm4adqK9x0pGxgwFwuBgdjuY6gKyAnLUpbC0E2mkLuuhQh0tAcYu9LIPpM/l+M\n" +
                "6c2DlhKdQ/I3KvPxjCpaUxTVQ6iX8OyocQlszKp+LWb4NRBnHYmBpiO5vSC3aBPg\n" +
                "Ga3ewshaPQBSsN7f29AEHSgh\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint0CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(pathLenConstraint0subCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca, trustAnchorRoot)

        shouldThrow<BasicConstraintsException> { chain.validate() }.apply {
            message shouldBe "pathLenConstraint violated at cert index 2."
        }
    }

    "Valid pathLenConstraint Test7" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQwIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "ZTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "NTAzBgNVBAMTLFZhbGlkIHBhdGhMZW5Db25zdHJhaW50IEVFIENlcnRpZmljYXRl\n" +
                "IFRlc3Q3MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4Fz+73nLTNQk\n" +
                "5wB39QOcOINSEMhrucw1kGkaAWyS8zQp4+EuqHs7Atb0XqZdnKldzOa4UYYbHIdv\n" +
                "72IZdyL2VVo3SKrPHZNm8CTcOvYUfLDJkieF8Jq3zlubKGfAxoVg6Nxs6XUs1TXC\n" +
                "zWZddqgaNi4s+NApxUFCEenTlv+LcoA4sEj4G3E1ElrqiP/iTGsMCfslVhWwXhGl\n" +
                "PN7BHLICNYVW9HyKdNnDKb2kbTg3sGs0lD7BvjVBq+sXXBsjRBgNq7YlpLaVu5JE\n" +
                "vnuTSUFRIUZsY/gKQr+xdS3oQegHLuej606PNbpXdngBHTQV7MYuOqf5uUGLa9/m\n" +
                "VdDJsXw4nwIDAQABo2swaTAfBgNVHSMEGDAWgBSbK7JKPJDFblABySK9Y84J8Yw9\n" +
                "+jAdBgNVHQ4EFgQUeVtfJzYHp65HDuqh3SrnkjIrRTUwDgYDVR0PAQH/BAQDAgTw\n" +
                "MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG9w0BAQsFAAOCAQEAbrtr\n" +
                "dAQUuu4yakUr42oGarOU8nJ2rEwFUelHSVXUmMN+rswPb4OrmBojrunFZs++xAkn\n" +
                "L5VVoGDgyuefaquBFvXYB911Dz+1O+7McLXgRCj22fJHgEDMnUFKah3I5bFuZHnP\n" +
                "RX+n12Up/9oxAHsafaTIQNhylkNbTO1N9dvnB9lqFGqNoyww45G5aFOVE55IeBhi\n" +
                "KZJ8U13zQ6lcxpbUcW/SSGrfDrQfJeJmWHf1nBSeQZgSKWMBlfbWTeuyscqSBBSN\n" +
                "3eZSFmyW/Ks0zj3qHGRtYi0/nFc1XpUWuzReS8DXKc6+YaAshT2jhzZctY5Ctmrv\n" +
                "sCRlwOfchMmn1w7FyQ==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint0CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate() }
    }

    "Valid pathLenConstraint Test8" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqjCCApKgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQwIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "ZTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "NTAzBgNVBAMTLFZhbGlkIHBhdGhMZW5Db25zdHJhaW50IEVFIENlcnRpZmljYXRl\n" +
                "IFRlc3Q4MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAveE/VqvYMxSY\n" +
                "iJYipDWVtsy+LSoYmzW01w7agtChJFU8nyyGfXETdXJXUhqOSQ3KHMNvheRWUChQ\n" +
                "LUApGvj+ZDYL+ABokDzyYxMpFmPs4GtaTWrVpSKNo+3e/hgYdm6/YpV4cr3whrrS\n" +
                "XAXSKoohKwcnJaXZEWFp8bCsyfo6Llp68moO4pXxey396KyGyiTHdU2AnHjx8Uvw\n" +
                "EsHFM2JRG4cQPGiDyEkteKtmliJcMI/q+o79TwXCEYzXNppTAiQ6imIDSySH3iZf\n" +
                "RtRMLrTtF3SbEl5tfTAji9nQd3H2kHbxbnT+4r85UGhRdkeJgvfbTcbNhbpGjnA9\n" +
                "WUbG+CWdPwIDAQABo3wwejAfBgNVHSMEGDAWgBSbK7JKPJDFblABySK9Y84J8Yw9\n" +
                "+jAdBgNVHQ4EFgQU+6vUASuM8lSGUTbsCFGmxWglc0wwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgH2MA0GCSqG\n" +
                "SIb3DQEBCwUAA4IBAQDDBgsAr0bbdHP9DpawET8C9+cNstGtLgnhqosVaNxheg4m\n" +
                "8xLOfbXJG9Y6l7Kuphw8TTCOgV4bto8eQM8tyZSr6lLZ7C3ER6Jwjw8GlrNNliFP\n" +
                "yPyyIGPTT/NG888eO9ALyGkCFNych1QKrIgCaTTkjCnDZ4AfUmOLBB5DPA/Ryhu7\n" +
                "VLxbwE/zIKLrRb+qRozC6mgZM/om459sQcvgQUQpjCrjZYD33ZLoGVhcs8Rb0TU9\n" +
                "/BA/pbqF9/0qsW5iwCq7tEm6Kz7vtVkJnLqOt7zlh14HY9QP4ddfQFbZxg0okyns\n" +
                "VADqsOn9RFxkZZdFSXKvYVRnndOtJplE/WBSg46l\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint0CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate() }
    }

    "Invalid pathLenConstraint Test9" {
        val pathLenConstraint6subCA0Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "UjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "IjAgBgNVBAMTGXBhdGhMZW5Db25zdHJhaW50NiBzdWJDQTAwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQDpgGQKv6ZtxqisbQnblDFKz1kj4LQRZTaRi6ly\n" +
                "jkFMlb1h8OE3Q2m2uQd/HnayH57gKKvjvo5mdYe9AxjZtQKlnfvLvnEckt/2jx8f\n" +
                "PnD1owh9WnFxPfKk5KXFe07v2S6PnDJB9KeD5gGrGGDBPFtnN81rJ6CgFuDmO1TY\n" +
                "WPJVlZm+xK1OCPP5iPUT5DiyE6ouVLlHO6IONz4XgeMfjEa9J4Y3n5V2J0w4pUzV\n" +
                "P/YZ+afXQY8r/Gh3Vyx0oKqdlYjDd60Ui8iw0SMd8DDyTaa9wW4LGDolYOjB7yna\n" +
                "gW//Sxd/MZVwmcKmq03ZAlEIs4ew/+fBPYqMox4SFI7AWwzXAgMBAAGjfzB9MB8G\n" +
                "A1UdIwQYMBaAFK+8ha7+TK7hjZcjiMilsWALuk7YMB0GA1UdDgQWBBTPdnaDc5Ak\n" +
                "x42jbWd861LA1NTtSDAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgB\n" +
                "ZQMCATABMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQADggEBAEB/\n" +
                "WsEKvQHARpddOd3k4ozzpgZ882UmNgb+9ILrMLhXnJUn6JWfSj2jSSmhDmiNqu3b\n" +
                "lmzVVDBvVQqufpSIUK7/GB35AELTgoeOtepDANoRA1LJDJWc0gUbtKvgtfvAPPVu\n" +
                "19CzmZrYLalyS+DMF6MWB8WfSrhtqdCKH7ndwNqBhW47mwO8OHAmpnGfCcvAbvMi\n" +
                "UzrW7IoONO8dyPmUyLiscuiYzceI5S/ht3LbS/xHQeqFPslESirnsMrLKIFewqVv\n" +
                "TG7ODfcxBGAT40Sa02WABO3qPzcVnDPqBuzWHXM7Z02JXOkzZqcjH9bYpmRhz1vU\n" +
                "ZmqzIuGDS7/JLvKJekw=\n" +
                "-----END CERTIFICATE-----\n"

        val pathLenConstraint6subsubCA00Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IHN1YkNBMDAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMFYxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMSYwJAYDVQQDEx1wYXRoTGVuQ29uc3RyYWludDYgc3Vic3ViQ0EwMDCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPzK+3Yt88gKSZVYm3rqWATIKudK\n" +
                "erzo6+8OfKXCeLhqdyl7YQSXA49uFUCP3j41d6D51ntK6ngrxNY0HzGIO76aGbqB\n" +
                "u1XCDdNUQGdL6j2IKBL1b3wWfbkFP7jQ4t57SKbtRVrJQUclQnPngCglKy9VSVME\n" +
                "xpO9FfmPMJi9UV+zZ2VXD/6wfe6WG+bwkGDh935dJXi/pRJEYcT9ldL38He+fTmu\n" +
                "pFatw7Z/qroGStY03BhsbNs5hGPk84ttMgf+HUcNWEKPrLmRzY0nmfAL3oRtfjNY\n" +
                "+V8N5BhcBHIXoiReaSUi68mkt7K//FzIOMa5F4tsyuiiElFMYebEV5M1pGcCAwEA\n" +
                "AaN/MH0wHwYDVR0jBBgwFoAUz3Z2g3OQJMeNo21nfOtSwNTU7UgwHQYDVR0OBBYE\n" +
                "FLq54oj31FkliuMp30+gBjjdcXSCMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAQoo7imYucTJXFumY1aMqG9EQSloP/zLPTdL6XFi1tUFCebI/pNhDIHOO\n" +
                "svVDSnenCEL2pf5V7obvFKBCb+IyaOQLC1JqV66Cti25xcyyVDKm0Bewd+ZydXYS\n" +
                "YxhGkPEzqPCPJ0z3Z46vI2ObJU/+s37+u6EUSfX+V7uKcrQhR+9DwfL+x/5b+TKg\n" +
                "l1kKIxaAw8hZGwOaAUdUTayCHPaxpGUFXqgfR52D2+fqIDFd59CwksvCUXx76qqW\n" +
                "5JOBQu7UMyTMZsv+ZWg++JcSjKd9/FMBGtmPRnu+HB4+XQ+I5f6lSi62FUQQQ3JX\n" +
                "MWTHU+R74FntihrR4lAAl5Qwh3N9pg==\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDozCCAougAwIBAgIBATANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEmMCQGA1UEAxMdcGF0aExl\n" +
                "bkNvbnN0cmFpbnQ2IHN1YnN1YkNBMDAwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMx\n" +
                "MDgzMDAwWjBnMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0\n" +
                "ZXMgMjAxMTE3MDUGA1UEAxMuSW52YWxpZCBwYXRoTGVuQ29uc3RyYWludCBFRSBD\n" +
                "ZXJ0aWZpY2F0ZSBUZXN0OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
                "ANLGB2+a1z3R1ROq3nfJr1wwDsswYFEnvsa/Wr3TmkHChPZaiqssCUawxeeCR1uu\n" +
                "FS9X+Lt3CTROXKQ0G3GujkpNxTP+tLTjzSIRUOaxcyN8AipiKL3wwBGm36Mvy5Nh\n" +
                "PGCOuQnvqpysvKtV4FOt+zlFZRpYnFR/Qom+v26vwECAPKmP86Uxs7o0umgUJtDd\n" +
                "Sk5ihTMqD/aZ+ig+dCze8Ornxe3fS6NrnnvLWKSB9APN8CI3q2DWaiN5HtSU7la3\n" +
                "m39Jzu/mPD2tEwrqJr9GZlj1Wgy3a0+zbHjiLYVQmXVcyfsH7LrQzXGuEMc1WKCo\n" +
                "5KZMqejlnBPgeVTs1fNFa70CAwEAAaNrMGkwHwYDVR0jBBgwFoAUurniiPfUWSWK\n" +
                "4ynfT6AGON1xdIIwHQYDVR0OBBYEFHkjxiIM9f+ESDif+mKJj9uEIvlSMA4GA1Ud\n" +
                "DwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQEL\n" +
                "BQADggEBAFDUrcx9Aq6taCu2kipVTgU4GQ9gJ/lEwCW6LP7p+D5iRJZsmXpXHIw3\n" +
                "YZDBgxGXJXHzUFzeBbySLu/lQfabnq0XcLViWhgi++Ikqr8MPxoqbUvQH412kdbe\n" +
                "b2Rf90fk3Mu31VrIBLbEp6U/h0QWWWPKJGcY+Z1jgdA14m3b1LPK7/p1kfT1yb3/\n" +
                "cTtmliG7wzcWsecmK5xz0irZrywun2yWQhcps5g+lhMcMghogHKEmN0XnFqgL7ta\n" +
                "beXQ4GEHuyyRoRuXrh2QMyDkFgr+CyqCbEQO3UKbvTQD1Q+jPkYpApi58UXxaKfa\n" +
                "JTfJg896LS1hDrZG1R2AOrhUFidhPXw=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint6CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(pathLenConstraint6subCA0Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(pathLenConstraint6subsubCA00Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca, trustAnchorRoot)

        shouldThrow<BasicConstraintsException> { chain.validate() }.apply {
            message shouldBe "pathLenConstraint violated at cert index 3."
        }
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
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRoot)

        shouldThrow<BasicConstraintsException> { chain.validate() }.apply {
            message shouldBe "pathLenConstraint violated at cert index 4."
        }
    }

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
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate() }
    }

    "Valid Self-Issued pathLenConstraint Test15" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpjCCAo6gAwIBAgIBBTANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQwIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "cjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "QjBABgNVBAMTOVZhbGlkIFNlbGYtSXNzdWVkIHBhdGhMZW5Db25zdHJhaW50IEVF\n" +
                "IENlcnRpZmljYXRlIFRlc3QxNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBALTPBtTph0kvovSb31pRYt9egyO+d7Eq9BtlSFiZ5UyYGh5UC2FGcDP4tzkO\n" +
                "5si6Vn4yZ/rwqIMNyU5bkbfludraX1b/Uc1kObROQfOgEApaE3JuZSVjXEwJsojM\n" +
                "yBYCf0FErkdYAgzDE5czPhH+NE5ENiI0+cox341aVJ17bK9wK48JP5ajt378Y7Uo\n" +
                "sLUG8hY6d5fOJvE9Jg2IvqCXLuSfWzJtCunT5Qlf6qASV0rrUJWdmKaqstNbqq9H\n" +
                "Cj+IpQJTrwkF/8rPkAnuJcjqRbCimdpVqYLqF6EPAv29rTBZyKd1qktm5n3wjcQ4\n" +
                "hWu4kEHG/KPfSC+pvk3OLa3FD5kCAwEAAaNrMGkwHwYDVR0jBBgwFoAUgOtzvk2Z\n" +
                "npS9F0ta989Xd3TDX3cwHQYDVR0OBBYEFMjr2VjA7usIwlcHbZp92KG3YZu4MA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcN\n" +
                "AQELBQADggEBAIKqRjt2Z9NVFsBaFffuOhB65G9/ZP0VnAz3x+5EKuUn2MhbZEnK\n" +
                "pMS6dDI51ot5gK7PtxyXH7DwI9Tq8BlkpU5UMspeKKwHuBe97IPsSeAFeQX2zkws\n" +
                "yz7KW5QIezi7ijyNtWHilzKeK0uMh5pMAkNVoLH++8d1PYgG04EYxZlHZTedGSj2\n" +
                "QjiBc2bJQ/hTQSoXjXlFK0auVmMOohKxYi6ZgWstGGDdoY+/1qe8vWBqn3e5NSLu\n" +
                "oqd3L3jD6g1rjc15SEadJfdQO7xMTdgnJWqij0N4rcxo6EzqFVvt8FGUNwCdHJFT\n" +
                "B1Qi4p0aWzKTaG/KcfnyuEyrAJB42RZI+LA=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint0CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(pathLenConstraint0SelfIssuedCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, selfIssuedCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate() }
    }

    "Invalid Self-Issued pathLenConstraint Test16" {
        val pathLenConstraint0subCA2Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlzCCAn+gAwIBAgIBBjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQwIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "UjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "IjAgBgNVBAMTGXBhdGhMZW5Db25zdHJhaW50MCBzdWJDQTIwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQDDwju2MX5clm28dBSlbJqozQEyqSyU2XEBKhVc\n" +
                "YhHCnnW4Mhqtx3HEFzG72XX5tAuLhjtpQjwYhoz1Q/vHdZrzG5/rtbthbeWrVbFa\n" +
                "pr+NS1CJqJWMFYfCITCOkWn4BoAzga7reEAsMGZzOsczR3RhtckeYQTfFj21H+pe\n" +
                "zCcJ0DESZpBW8QAPvRm9fryCl81O3aYAV+bhz5ssnL3hhNtn5Ll1ZDVALkOXtOqC\n" +
                "sJEkDQNJTaXROuRqUCs4dr/uLHVlOVbhlv+oND5n2ASTcgeyOra4PO24ZqKnmGUJ\n" +
                "8QSDeMVZ+pauI6mF3MRWouEGQfQVdvXE4jJFueTa/EvvOsG5AgMBAAGjfDB6MB8G\n" +
                "A1UdIwQYMBaAFIDrc75NmZ6UvRdLWvfPV3d0w193MB0GA1UdDgQWBBTGCSob+7jp\n" +
                "PmhgeseXzrNYUXt23jAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgB\n" +
                "ZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJZghcKY\n" +
                "Ek73C7WdWGwfUEVjvhM0L/R5LGNzvHur2Oo3Z3Yw3/J68QNKqtge2W9gMl3xQ3iv\n" +
                "T2wu8Llxq3rDtMAuVKM29n9UK+rxL6GTb9/n5tgdE9UVQhzKaNvvR1pzTGmqne3V\n" +
                "xHMi7bf3aC/1GVs051DMqPi99tFUCe761r+gvwQShcDVXRHKtK0bidx7BSKdiG3n\n" +
                "1b+EbF6w0/xmPpIpP5L1XFJBfnpclNr57zopBNjsr5yuZ8FM17L7jynSlvbJozlS\n" +
                "EXMUORtLZr9e49iI0vRU8+FqwMEpMsFdHY8fTnBkO1x/01O3x5RRBeYf3Jekmoq7\n" +
                "q0KsUdvxjpd/KeE=\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDrDCCApSgAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcGF0aExl\n" +
                "bkNvbnN0cmFpbnQwIHN1YkNBMjAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMHQxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMUQwQgYDVQQDEztJbnZhbGlkIFNlbGYtSXNzdWVkIHBhdGhMZW5Db25zdHJh\n" +
                "aW50IEVFIENlcnRpZmljYXRlIFRlc3QxNjCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                "ADCCAQoCggEBAMUAJaSBrAZoZKqqNKxkwBcU+6HyF8FbDUmVONn7QXBreqY5hP/u\n" +
                "iH4t1VgIIQfYuDq4KuFG8w+j8XlwNyG1/LRipLXAGFPTthfve4YqxksDMlEtjKEv\n" +
                "6/Ed2/u27iRmTN4Xclfae50TcS/lPI7LcGhA3xb8i1zRV9jhwSOze/lUrH7w7XTd\n" +
                "S0l+PZXwjFlz4rQF0nglux9GWUIIfi6j98lKkSlozIJ+i9UheODwktnaLcYIJdvW\n" +
                "fh7c5g023RzmkF35VetdYnalZRQuAoqxRMMMJbUP4fQdHePTSG4N4tazyjeFebnE\n" +
                "bvZcaXaTpXPe4EGW4oLQQ4yg6RP5f3hQEkECAwEAAaNrMGkwHwYDVR0jBBgwFoAU\n" +
                "xgkqG/u46T5oYHrHl86zWFF7dt4wHQYDVR0OBBYEFPfHm47xpBBMA/uidLHze1WU\n" +
                "6Yn1MA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJ\n" +
                "KoZIhvcNAQELBQADggEBAEaV6lhnnBOu4mwaZuNF2UldqMeLtPZchw0uoVW0fwjL\n" +
                "9BLVSV6A8kwJnxINPrpcCOY56IHjfYR8cT1cbGRABEq+FDsdNFhRLXnUWnaPprGW\n" +
                "fZo/Fb1KS6EfGupVp2h3jKG8fsSD81KfRaJNc/jbEJi0vKoHIlW87/SHk1B2sN57\n" +
                "wMWG1d13zwbVULq34Dr125HMU4kgvvwyBPx2pf3tf4mAeXK8WlLyu5s3aTrLACso\n" +
                "ZYRkh6hcY+LNx5nUa6xwU6LmwNg6VgnHu4aHCrjcofFDcF9Ww488XisnugMVo7FR\n" +
                "8QiAz8k5MWqiBbvpfHkgvWLOdpj56uvH+waD3GjD+04=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint0CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(pathLenConstraint0SelfIssuedCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(pathLenConstraint0subCA2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldThrow<BasicConstraintsException> { chain.validate() }.apply {
            message shouldBe "pathLenConstraint violated at cert index 3."
        }
    }

    "Valid Self-Issued pathLenConstraint Test17" {
        val pathLenConstraint1CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjTCCAnWgAwIBAgIBHDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHjAcBgNVBAMT\n" +
                "FXBhdGhMZW5Db25zdHJhaW50MSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
                "AQoCggEBAMPMeBPiR7BFGHpvlxWNf9ogcUB61rzOlXR3ZzeDZsb+hslxASASvWVB\n" +
                "nCbMGwoQyYVuCOLiWkTaZRxg+Xf7ZrdZUqu1MBNISS6xpjNsgk8SoDwRJtN/TZFo\n" +
                "E2LpE90VAJRv0KBFrwT0CTAD24xCLF3y2zBLPX+lcjySi5HPshDckNHnARdxZ1B9\n" +
                "m05bm4mDIqicBxFLqz33UZv9zNQ9E7UPike4HEdJ4vcio5eUtx0WPdeLXVw/zXfG\n" +
                "qgDdRpSsEZPrSC7WkWigblGL+/5v3XpjuUL52ecX4egBKY18lL/Mi/7IGOrWE1/q\n" +
                "4ucPM5lj2DVmGJ2PC8vWXyMdqjy27lMCAwEAAaN/MH0wHwYDVR0jBBgwFoAU5H1f\n" +
                "0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFPPkcWD/FxTejSaFM34c/MFHZ/rB\n" +
                "MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwEgYDVR0T\n" +
                "AQH/BAgwBgEB/wIBATANBgkqhkiG9w0BAQsFAAOCAQEANk4qiCIoQEqCO3v/6FaO\n" +
                "StfIEVgimKiuVHCxSdRdvU/53ullYEWRonqoGRGh4LLj+oJO+JgWYmstphMNPgQ6\n" +
                "edML21rMH8HYOsj/VuT1akNeyuXT9vwIusPP1UMSkmYu2YehIFzJijxZ0jitX8Xh\n" +
                "qfkip9xpgQi/R9e8Ad1prvQyhZvFvxkNTXwU/V2oZvvAcBZhsH3dZteTLc5dl18K\n" +
                "4wRO2kcU6NBww3W6JtvHIFHKvwihyUpZckc5CrmvAkNopP6DCF3nUW8V3OBrN0gr\n" +
                "7g8Vrt7Tx0OkWNUyJ/uInPrpCYh4IrXAyd94UT5L3H1lj+tNYY+NdWeOhkYafjSr\n" +
                "2A==\n" +
                "-----END CERTIFICATE-----\n"

        val pathLenConstraint1SelfIssuedCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkzCCAnugAwIBAgIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQxIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "TjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "HjAcBgNVBAMTFXBhdGhMZW5Db25zdHJhaW50MSBDQTCCASIwDQYJKoZIhvcNAQEB\n" +
                "BQADggEPADCCAQoCggEBALt/+8RsBtPmiqfzvoksZfA2tnzXWqaI9We0vP+zCNAn\n" +
                "g3iq7xtccZB1wczjSs90P07TGNAo0kgzvRW4Cr1H66e8lpd7pj4TJtkW1lnaKQAF\n" +
                "DGvF3fhGFgfDUPhTeHfEpaeJ2IPB8WfuDfaCvUkmSXkLo18Q0CTzW6GHr6Cc35iH\n" +
                "3njaGcppyCgxRI4Dxn8I3civKNhjV0I/x5A/KXBh+Zz6eDRZaQABZqHaPwo8Y6hm\n" +
                "KaXyAp8HhiEphaGS709jloFQAbS82FZEtUVD9Arrd3a2+cSXfhCgBV79sOX0tTYK\n" +
                "Wzmk9kRWiRD9TZFSepIKlwsployk2rD+V48YyQ2wg1ECAwEAAaN8MHowHwYDVR0j\n" +
                "BBgwFoAU8+RxYP8XFN6NJoUzfhz8wUdn+sEwHQYDVR0OBBYEFDS9ZOOfjm6YJQDb\n" +
                "ZTauNAiV650HMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIB\n" +
                "MAEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEATw49Gv/qJNHn\n" +
                "DrsMkLN8NPb3Yk99ATawO+03jybiYqsrr2w+r2aJdRHC2dRoAZEpkQRceaSI1LpX\n" +
                "gESU9z5kNpVYCC/kRtqmWPPGd7/zYfzRG5shGVtPkqDjyhc7J0PJdTqWKafDosVq\n" +
                "rOhNJmpRr/u7wrD/oQHxHcjqXpcKW1BoZdJyCd74jQG/89gG7PoUcz1WYFSwnOh5\n" +
                "uU2zMFbp5w1b7eXBRBZ5604dFrbCATLbdqSXDTYvCuoRGknWHbM2eSFcwlddEvKu\n" +
                "Q26ZnAEbSmtoGCZhC1tQ9ymT0IxgFr/kEA+TbE8PwPbeVExckBmYVYSZ0YbOaDbv\n" +
                "KzHycDsvVQ==\n" +
                "-----END CERTIFICATE-----\n"

        val pathLenConstraint1subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDljCCAn6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEeMBwGA1UEAxMVcGF0aExl\n" +
                "bkNvbnN0cmFpbnQxIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFow\n" +
                "UTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
                "ITAfBgNVBAMTGHBhdGhMZW5Db25zdHJhaW50MSBzdWJDQTCCASIwDQYJKoZIhvcN\n" +
                "AQEBBQADggEPADCCAQoCggEBAL4T7DpvoO/ymsui7e6SJaKtxNET+dImelMFK7Ao\n" +
                "PzGGaXiDHKbPPV82MQVEICaeDZ+CWe8+tCRGEttlf3xFplzOg7glM0itFpGWhe88\n" +
                "OtUwj4hLG6TBqu1W2dJU3B+JghpHO67brDoO+AQxt2juJIknR2AwYwgr0MoylA8h\n" +
                "TjSVd6aLsQfaRLdjGLEzbev7Ktj1LkRbykGx0FeoGiEbj/fW1Nl3RJGS9aeiQnPL\n" +
                "FoxjNAQ9vDOMB+xEzLEVYZAHvXVvtYGxAHywrPYZbAvrmm2fty3sLN0g//uJvbOZ\n" +
                "2EbL601Qu1MAp7yFhDFl7YcsQxQORkfx3gO/noeud5np1KsCAwEAAaN8MHowHwYD\n" +
                "VR0jBBgwFoAUNL1k45+ObpglANtlNq40CJXrnQcwHQYDVR0OBBYEFOWZlrXHfVVC\n" +
                "rYGOxyX2GM2snZB5MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFl\n" +
                "AwIBMAEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAS0A82n0i\n" +
                "4CFz8P1KHyyPaO4QK8v834S0An0Nx2G/zEcQM2SVYDjVKbls7mNN3KxtaMmv1fS0\n" +
                "kfdPzYAvu7asEHTRaM2854OI+zBIOZw0l90/4cCxdf2eUCphmgKehy9CZ3BHEqVE\n" +
                "iPJM3+/XAxlU2WuGWblNiHOFHKl5rXlkGSBscu4OV5NHay75q5nC/LVaMdugWSAe\n" +
                "xOOHiLnV+H3Z+rx95aa5/uMn1TL+N+QY++cC/ug/vxlfOEeFhCWc8VhuqzGNtFlW\n" +
                "Z1FR01Q6Rxs8xRnyOzZs57dTdSA1bDu1TnZYelrn7N5x+RlYixJA6M9fM/kweeDa\n" +
                "WlQQJJGrznvK8g==\n" +
                "-----END CERTIFICATE-----\n"

        val pathLenConstraint1SelfIssuedsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYcGF0aExl\n" +
                "bkNvbnN0cmFpbnQxIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowUTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExITAfBgNVBAMTGHBhdGhMZW5Db25zdHJhaW50MSBzdWJDQTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKZG3pTPn+SJPMjCLTMtG2fYzkP+dDAXVAVI\n" +
                "l3fw5wsUeCwNjyYOa0sWOGp2q6QrBgGhVUMi/IAw0y7YzE1BWOyf0zAxVKSjTNvi\n" +
                "zm2sYeC7eH5J+Yf7c179F0SLa3GwuDf9z18z8gSa/mtqszclsDK7SqRQ+wC3cer/\n" +
                "XHZ0KfiAhON7XLkhuFoInS1SlvYmy+KCSJ6898kqWLhx4KG5kty77HvnB4uUeCCK\n" +
                "zhaIaTTK91r/R1LCGpeU6L6TB7O4wi+SI+tkmyIqy6MUOG7wEEgza8ACGOT6cEVF\n" +
                "GcJyX7dzo0BJ9J+WcSdsK/Ugh9WIqyCSNA20sHFVOYq+qOWuanECAwEAAaN8MHow\n" +
                "HwYDVR0jBBgwFoAU5ZmWtcd9VUKtgY7HJfYYzaydkHkwHQYDVR0OBBYEFHkDh1Mp\n" +
                "Oh6+6NQY5QQ0gyudEcfWMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCG\n" +
                "SAFlAwIBMAEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEACZ+k\n" +
                "jPBCnY1vtT62m30fHrzOBlIhF7BxGFRLElq+cz1caazoP1UwvI2U/NKzjtdjYIQU\n" +
                "5KI1G99HmxQE1P3Lao0GK7SMi7PrfZke+ULWCa1/NviZgj1wZIecK+o930xlXemo\n" +
                "xLYT5kyDEQTaKXLEmwWVZA4YZZybcrDrGYzjcYmhVVRId10zAHqos+Md2E8OHa1Y\n" +
                "q1i0lpS/3DjkHhWmOOv99c4Bs5TwmW6IRNjYYdnPpL69XyeIaVheU2KXIxVxrdhp\n" +
                "hLn4CRDQ6SeZl4zb3WzrBKLWcLJm4JM/OTGRb0LsV6Qba0StWp0995lGi+tqySuU\n" +
                "slTcCndmiCcZady6vw==\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqTCCApGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYcGF0aExl\n" +
                "bkNvbnN0cmFpbnQxIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowcjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExQjBABgNVBAMTOVZhbGlkIFNlbGYtSXNzdWVkIHBhdGhMZW5Db25zdHJhaW50\n" +
                "IEVFIENlcnRpZmljYXRlIFRlc3QxNzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
                "AQoCggEBAKZ/110TQ4OpgLh88109wvt/7WJQ1YHMugQV99n4Pu3kdI1VQO4ckrNq\n" +
                "m+LBgYBgZ4Z6EswBTKiEmP46zxnhjiM2j3NXU/qmWvrH/mr1z5gME2iJZgO9r9Lf\n" +
                "96Bi18e+hA3D8TvaCvZWSJJRyRcGb6eMFPW2YVb4lTUetmaSlI/RW+4nUghXyww2\n" +
                "SyWnugMA3lS2zg34mchaDWI1OGpDV7HlYI59pPPfdhuGmaZ++dWbtB7EcB8FtQX2\n" +
                "y30Rajgn8P5J2I7/bl4Y7GLbQMZQoLlG7zjC/OCfew/EmJbzowST3P/SauI0j8xZ\n" +
                "8ZLW7B6/EhdaiUBSyv1zv6WG+zl8/RcCAwEAAaNrMGkwHwYDVR0jBBgwFoAUeQOH\n" +
                "Uyk6Hr7o1BjlBDSDK50Rx9YwHQYDVR0OBBYEFB7n3xAM8NB1qQnavi3TtjaSwfmT\n" +
                "MA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZI\n" +
                "hvcNAQELBQADggEBABZWiiHlZ/a+B0lgBpqprSf/4g2EZOQDPmGOnIm+UhdD3ahy\n" +
                "z4eVaeNlr+ksEkxeFW+VHOTsoQWEJm01WMgr3m4DJe/VJnyZP3/yKlEZ+IVj5IKD\n" +
                "hfxsatOwWgETAH7vVlpjLjoH5z1PJsXWKP+Jxa1P1J0DQFA77osQHcWb6m9FUTkq\n" +
                "EMSv6FYZgTULTfF0EILCP/ldsQvu6YMXeJr0R7QEQ8w1Oe7jujOq2E+kH+LA7t7b\n" +
                "AxlFz9YFxyxw9ZFTvhCw7qjRijgaHSiT/V6L4uc1p3G5d6tFt6Az+rhsC/3lyYuY\n" +
                "QDF9LwIhI979SrewoXdbX7LPMQJXRAxBr3eGLn8=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(pathLenConstraint1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(pathLenConstraint1SelfIssuedCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(pathLenConstraint1subCACert).getOrThrow()
        val subSelfIssuedCa = X509Certificate.decodeFromPem(pathLenConstraint1SelfIssuedsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSelfIssuedCa, subCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate() }
    }
})