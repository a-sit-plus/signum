package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificatePolicyException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.CertificatePoliciesExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.Qualifier
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

/*
* PKITS 4.8 Certificate Policies
* */
open class CertificatePoliciesTest : FreeSpec({

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

    val policiesP2subCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDgTCCAmmgAwIBAgIBEDANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
            "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMEoxCzAJBgNVBAYTAlVT\n" +
            "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQDExFQb2xp\n" +
            "Y2llcyBQMiBzdWJDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAONY\n" +
            "pdHnfkkbKL2heQlsPDaTK3GP8UpxbIYB1XqtUGkKluuwcYbuk5IP8Epdq/PjxCzq\n" +
            "jS+3tTzOFpNKRk1722cL9fszIEVupG0F69OvZ3LLiz7UxvtTQcPHYdBrOmuJGr/j\n" +
            "R9Qie+7F9teXcKCdITo+5Zx65qrcR2GWoG0kqorbgEg5ckFeKoe+GnMJeR/HyzhX\n" +
            "LQhi6BnJEwjFCmhcTNkdxUiIEOgNqV5A5mxYq8Q48bTaQTBkU+1UanUriLd0qcqN\n" +
            "3uT+ZlvFU29GHZ503xNV0YMisbl4VERoBPZgJb5nIZoPyejMkpiVMTMYiIjCpzwe\n" +
            "4BRFEJJNI+5NhUrReDkCAwEAAaN8MHowHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2l\n" +
            "EHIUUfWvOskwHQYDVR0OBBYEFF48hHOeMHBycZiugTYZ2yIOfK8DMA4GA1UdDwEB\n" +
            "/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEw\n" +
            "AjANBgkqhkiG9w0BAQsFAAOCAQEAdGtNBQ2x5Q2dsg3CvXxLjMO5Ij7kWTJ//BY9\n" +
            "2QuZ/zZrVlYdCn4zquXXdGo96fSqJy4vK+ERQCVk9uHNs3jTSoQRN0vYGnKoKt85\n" +
            "rEeMDvmahO44MQaOZlG13PwlleVy598Cu7Ylis1mnq5s3oDozMau6QZZIljdt6VE\n" +
            "OernrHHcr4EmEmw1HuCIZZf8xcai4hqcrXw5GJPGr34uU6fedvmaKp1/1WWHPoEk\n" +
            "O5CAiMmo8t/yeYWL1HmVkwvEwHJ79IXZFi8sIyO/8HCufS6DD1FthFlQfBuYHdjo\n" +
            "fReXC5SMPIxbpHXMAUPJgTwm6HoO9/XW0WzLxCXvu9pMDDD1IA==\n" +
            "-----END CERTIFICATE-----"

    val policiesP123CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDsTCCApmgAwIBAgIBJDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowSTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExGTAXBgNVBAMT\n" +
            "EFBvbGljaWVzIFAxMjMgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
            "AQCffODGihp4HxePe48+r7DuaPS/JNmLYWY1/38FcOJvrd8p1tZIEpi/bgjs6JdW\n" +
            "n2T5FPfFbQaRiM5Do/3VH5oWxQIZuJi1Wwk1aENpSUZxyXhTDERdgWiMMxWi/4+j\n" +
            "IX4xb2PX39awlmgArgJpBSHI3H0uqBYTOG9+zt4RUhd5aXXmq6boQA91euaSmXaG\n" +
            "Y18WP4ehf55cJU7R138Ngbtne1QTE2DX0Z0ylBfS+dWSDnE22BMpcI2I3kFE12Wr\n" +
            "1q2yyAtWIsN9ZH/DONL1nqUvqRw+boil1ELtr7QSlBFlYX/+mPwnDOJL8kfjRLlj\n" +
            "RVZYzVZpPQBxkf1P5s/VWMuHAgMBAAGjgacwgaQwHwYDVR0jBBgwFoAU5H1f0VyV\n" +
            "hggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFIwoCtoNCRRi7j09lrhxkxKJ6uhjMA4G\n" +
            "A1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAwGA1UdJAQFMAOAAQAwMwYD\n" +
            "VR0gBCwwKjAMBgpghkgBZQMCATABMAwGCmCGSAFlAwIBMAIwDAYKYIZIAWUDAgEw\n" +
            "AzANBgkqhkiG9w0BAQsFAAOCAQEAK0X1I254izkWRa0Za2Ur/XYzrvZO+EF6AECL\n" +
            "1EX1WCaVHxWawOIgZzfJpUHER7b52m9Tn6iTwRj+jJ40O1fjpW77TX+ooe62OgDr\n" +
            "nxni6ZRq+aq6epkwe2YtdcIa+Qgb8PGKwW/WR0ucI6FnG38fuKa3YF6dzQUQKptH\n" +
            "CWLoaAdo7Bb4R8nqdQeHFX1XHp8Pqw5mGBCuFAIr65gE0cqlefFs4fS7aAISF2rc\n" +
            "ORHW9/7kUT2subzmmUmuzbiZHmO9cT4ozph7hrjVNjtN7STrU0PBEAHPw8E77usR\n" +
            "KXb0M/xu8T5bHkVo347HGIsj5iyt/B564Swpv+BJ5ZlQwIuJDA==\n" +
            "-----END CERTIFICATE-----"

    val policiesP123subCAP12Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDnzCCAoegAwIBAgIBATANBgkqhkiG9w0BAQsFADBJMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEZMBcGA1UEAxMQUG9saWNp\n" +
            "ZXMgUDEyMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaME8xCzAJ\n" +
            "BgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMR8wHQYD\n" +
            "VQQDExZQb2xpY2llcyBQMTIzIHN1YkNBUDEyMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
            "AQ8AMIIBCgKCAQEArUStqR4b0h47BHbAWPMcIloYkfa4ASeY9bqzOejwnoJWbjR3\n" +
            "80zGBLHB9BpGM658Nzr0hFJ8lgPAOnAoe3CzHSm7Inkgh+G0LfIFiRh8QpJagzmD\n" +
            "Drz++lB+0iW9NwnfbxgQz6BlnddAWAY8Za+mvx1y09LE1r5mkfl4+cZh7pCSLekv\n" +
            "eR2rw9nn9IbovnEg9Hn2f0JX586nNjL/3N/VB94OcnfZRe3Gn4UHlZBxwa6RplSs\n" +
            "uDweO+g8oPN9QN9j20CP10Q22JYsZuvHPE03hjWylbbxcqrpUIDKOyehygI1K6K1\n" +
            "7r9CWuSrRzPcQe4ccs6ef+1PN5WZbm91NAXWPwIDAQABo4GLMIGIMB8GA1UdIwQY\n" +
            "MBaAFIwoCtoNCRRi7j09lrhxkxKJ6uhjMB0GA1UdDgQWBBTOANr9qpNA+MCgea3B\n" +
            "eM4d1yf2njAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAlBgNVHSAE\n" +
            "HjAcMAwGCmCGSAFlAwIBMAEwDAYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsFAAOC\n" +
            "AQEAV1edqpMmp2JfG73MOcPw3zffoQYGSf3UlbJf6rbmtcBwiKzjYvH2BqvdD0Pz\n" +
            "wx+Ph6rRvTyuqF6XkAodMYU343ZnS7b62wtlx0XhoJTGSeinwsIFQsVuKdTfdQgS\n" +
            "bSDGI4QHrSzjyjeFdk4sxyP9kGcKSqqwxTGJ2XWDPV24WWm6oeNkBOuQV0WmUigF\n" +
            "vOBAohaCXhEyIhJrp3vYT/hmL9hE0BLgRO/mgYaZQq14GK8E/LfzRSA5eBQCCQTc\n" +
            "iTPJ2rMVXMV3B79Hwa9dBuXpfVCNfafquNa87x//iBZ8kTREbBUc6mRQzpGNAnOE\n" +
            "59OCcPtzlrEhGwmwAe14N3rCwQ==\n" +
            "-----END CERTIFICATE-----"

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

    val anyPolicyCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDizCCAnOgAwIBAgIBJjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFTATBgNVBAMT\n" +
            "DGFueVBvbGljeSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7o\n" +
            "J91PNM3AvPFePimzLAnnv+BRwQSrqafBm/nheXXLVtOtfNSoTqBWoo5uF4rGyYHF\n" +
            "MRHPORNZjZRBoxHho/SWM2J7r7hOOL+JJjMYwZhCPkxXjATXNIXIolacHxARaT9a\n" +
            "XjfnPAtmAotI+91ZMaHiRup87ygHHtuD3Atpe0NNbnqbQzmpA2+bwqv8Ojou+40i\n" +
            "1NHVTgVDk2mH3HQbPzh2C3p2CIrhPv8IDpxZcdkEkAaMUK+czXt3OEMnqzerKSOZ\n" +
            "8UVxdjYtJoOeDg2Pq0qNqbwW3lXL6+PNH/zU63fr3Nqz5befHyTS421OlEIK8FtU\n" +
            "lEQ3V2/JBQENdlugwXsCAwEAAaOBhTCBgjAfBgNVHSMEGDAWgBTkfV/RXJWGCCwF\n" +
            "rr51tmWn2V2oZjAdBgNVHQ4EFgQUu8neyByV50LikKKOrgNcqyRgfoUwDgYDVR0P\n" +
            "AQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDAYDVR0kBAUwA4ABADARBgNVHSAE\n" +
            "CjAIMAYGBFUdIAAwDQYJKoZIhvcNAQELBQADggEBAD11IPBOgXaljMw5AvmAXBLG\n" +
            "LPx4zhX/UmT57NlW3Y/jbDb6MxglZr/YsXyUo8Nu3PkdqbO9mwfzfcmLrnuHrdSj\n" +
            "ud2jlR1VEZz+7uzPDPzP89u+wjA0UYlKahHvgFTRedUZ5FhN6Y7iyP5b6Iq4Gb6A\n" +
            "bhJLq59d0RXRsVOhgAWBo0xTO5s4e7vhzKHCQLHkTbD1g/HLW0ae7aFfCT30PpFP\n" +
            "UhBHfwkD5tdW/8qcejbs0fpegaiVtOzwE6/Rwkuh4wDoszXQJo7yOsFyGtn7+ord\n" +
            "M3PS80suV01q67BmW2M6F6oAU3agb4guzMCw/3d7F+Ow9d7Qq5CjabaW38Gb/OA=\n" +
            "-----END CERTIFICATE-----"

    "All Certificates Same Policy Test1" {
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

        var context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            explicitPolicyRequired = true
        )
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            explicitPolicyRequired = true,
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            explicitPolicyRequired = true,
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo))
        )
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            explicitPolicyRequired = true,
            initialPolicies = setOf(
                ObjectIdentifier(NISTTestPolicyOne),
                ObjectIdentifier(NISTTestPolicyTwo)
            )
        )
        shouldNotThrow<Throwable> { chain.validate(context) }
    }

    "All Certificates No Policies Test2" {
        val noPoliciesCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDajCCAlKgAwIBAgIBIjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFzAVBgNVBAMT\n" +
                "Dk5vIFBvbGljaWVzIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n" +
                "1rGRRtklAdQBZAIICc8jB889UiuPhuz42qkRhIXsu7pLBvoK6CJRcKDODBkxmoUc\n" +
                "qkmyf2+6WIPK706gZ6ICLlaZJtU9XTG4+VdVe1hA09jjKmYQ5/RUoFto2Qn/jfqt\n" +
                "jAnEgoiJuTpGbhMNcIqmUB8e9U6xF0n8wKRuoO352ZNmKkslQMg9IDTD2CTeg8UB\n" +
                "Q5FIlTX+6ePUKgw49//7q6hdsOOsun19/Hc7zGfjI+ntqFpHXEL50sckzKVMO05F\n" +
                "9qwVg5+4a3bL13QHFDUf71SqIaXyh3S2UkvSphEbyVz/XU5oF5mMnoZWsXn+QbR0\n" +
                "gNqQlHGoqA7q5s78WqUDDwIDAQABo2MwYTAfBgNVHSMEGDAWgBTkfV/RXJWGCCwF\n" +
                "rr51tmWn2V2oZjAdBgNVHQ4EFgQUQiQD7aVLdpyXmFx06gU6G/w15JwwDgYDVR0P\n" +
                "AQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB5U\n" +
                "gIV++5zaqU8TC9lSIq4uTTo+6Q81DBD7Fa7PWhFLqF9cKoZ+VFDnIPQVVhz4laar\n" +
                "9Gtiz3Ix8vqGP6gPo5p+wpspJ13VF2YQqe61ZsOg0Mh15FETqEjvl6WZeVjdIvfR\n" +
                "p6xsD+h3T++Am1eYNaAwieBZVi8OGRJGaMSS4Q2RNXs0vzT5I4RnPcYwzLQsE1jT\n" +
                "7xkAkoNMHPaSMPAiQtfYHX2TqMn42Bp2CFuIIiDoZeKntLuo/vqKe28UW/d/uoUl\n" +
                "1wE635wC9nhd+YzvbO6vVVjT77sz0H7KWbMA8kn3nx4HNNhVGC5CAtqtZKpQ71MU\n" +
                "MnIgZeKsGC348hVKpRI=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDfjCCAmagAwIBAgIBATANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEXMBUGA1UEAxMOTm8gUG9s\n" +
                "aWNpZXMgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBqMQswCQYD\n" +
                "VQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTE6MDgGA1UE\n" +
                "AxMxQWxsIENlcnRpZmljYXRlcyBObyBQb2xpY2llcyBFRSBDZXJ0aWZpY2F0ZSBU\n" +
                "ZXN0MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL6WDyHxhLZpA4ge\n" +
                "LxU8BbeIOR03CkUXr/Vvnl1X/ncT1gvBBBnQ7Po7o90+gGpGzBPMjif4gMSkUJ8q\n" +
                "Q+R0STU5SIHBBPl3mxEKU6htvRX47h0hvUzRWKnN2lvQyzD4GkwQhJC7Tv2TDLCr\n" +
                "tVm5E324xPUAmBYLnbILJ4yQjLXWIa+usF0r1rm0L77cjkVz7HQp9hT/VAOEof8u\n" +
                "/TWuHTr6CoPEJQLsybS6/tP9WbyD3aPS0F/X//QGM2jwbVVcwlkuodxKrFz5DaMb\n" +
                "D4EaG5cr5NdDyjbnd71OUXG6j/LuQYuRb2fmXo3YQE3KK6/iStbqEudSUqma7DdD\n" +
                "7PhI3McCAwEAAaNSMFAwHwYDVR0jBBgwFoAUQiQD7aVLdpyXmFx06gU6G/w15Jww\n" +
                "HQYDVR0OBBYEFNpNr/S+ZFlUsYAeWIckHljqxZp+MA4GA1UdDwEB/wQEAwIE8DAN\n" +
                "BgkqhkiG9w0BAQsFAAOCAQEA0xqFOkeCtxlsvCwBTB4pfZNN6qpoRnJFjYD7vmaU\n" +
                "6XJQAO2EUUCVefK8eYoxPYwgbg2uTYk4HtTTF4cbvsr04hNjh0rBm7F0X7BlyvcF\n" +
                "TLBW7FEk5aAKjtNGca9kJw7aPo/5vaDkPjnrwTwkUBzEfRveXJE8JqS7KIL/0+SS\n" +
                "QCNhqf/Fn9KOpcwhQRKZXLcLlvVGtAqkexNM8ZNWuSLidt1Aeihudf0h/dC7g/fx\n" +
                "NTGfhBSvoKVyGS3AdadQvv9Ce3l2IY3P1NAczdaY/RY+gE2ccmEiRSc3IXETiUXj\n" +
                "gyzsUXK129XEY9fOQ88ns7RLifh3JBp4NhIvCx0oDWcezQ==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(noPoliciesCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }

        val context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            explicitPolicyRequired = true
        )
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Different Policies Test3" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkDCCAnigAwIBAgIBATANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEaMBgGA1UEAxMRUG9saWNp\n" +
                "ZXMgUDIgc3ViQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBgMQsw\n" +
                "CQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEwMC4G\n" +
                "A1UEAxMnRGlmZmVyZW50IFBvbGljaWVzIEVFIENlcnRpZmljYXRlIFRlc3QzMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2L32QT0g01F68LYjocgXqdQT\n" +
                "T3dlBxvACUPsrp2+NKeweuoSK2yPKvs/QN4Ce4ox41QANy0KredM+kotXEl38eDC\n" +
                "PTdSueu4Aib8XwXqNN47H0jXb3GXebDzdSdJRbrkLvV4hNYaf/PVWxtKdL/W4R7Y\n" +
                "zWCisxXow4MIXFcGS29ZGcx4yReMxwZ1UCbk0Vg7lfxIIsM0AJ7mCKXWKpGAYxrl\n" +
                "nAOjI1fvdD/NdEncadoeBL/Nv0wa9MA1k+EumSoPggSSZEmQJICZOJMeEiI12Lqv\n" +
                "oOgbPaCkDIlpnRzk06h8D2JC1LxIxoX56lSkzQKLBBtS0X4Y0LNOqjHUr0KZYwID\n" +
                "AQABo2swaTAfBgNVHSMEGDAWgBRePIRznjBwcnGYroE2GdsiDnyvAzAdBgNVHQ4E\n" +
                "FgQUWCD2nzAOZgQ9p8fRaOygrwpU7vYwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQ\n" +
                "MA4wDAYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsFAAOCAQEAZKkhGrleiJkNwbr5\n" +
                "/sNaPHcU8EvmcsUyyxHIUoQmXOcVDAFiUxs0TVTDoopeTMD6Mw/H2HXX1EOz41dI\n" +
                "MiHRWAZGKl9v1Y0t67D5aNoZly9QZxm7hkZ7O9SdC2pdE3y9xyQK4cTIafEedLLh\n" +
                "2+qOIFhB8GZlU+drtdCV9SVK+1R2vcurVkTHYeOeK7Clisfo4vEdhqFNnxKtnIvu\n" +
                "+LXurxBQvol14NuLoOTPvysuR+K9oNogoAUZMbpy76fkDO4usRkrE3+cJb3kx/pd\n" +
                "W1BlJ95+daVa30HVXq+jD1VwFyoX9wonijkfjgmk/nWBxjgeVxk/xwAdvF0qI8CH\n" +
                "Ggqn5g==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(policiesP2subCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }

        var context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            explicitPolicyRequired = true
        )
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            explicitPolicyRequired = true,
            initialPolicies = setOf(
                ObjectIdentifier(NISTTestPolicyOne),
                ObjectIdentifier(NISTTestPolicyTwo)
            )
        )
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Different Policies Test4" {
        val goodSubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDijCCAnKgAwIBAgIBETANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMEMxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRMwEQYDVQQDEwpHb29k\n" +
                "IHN1YkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsg6YlsgUI+Jx\n" +
                "eULQ+eIB+57x/d39rz5zlcqfjzxk95+il+BC1o3VuwtIIxYMSNmi/5GvBuGLtjA0\n" +
                "/XLCvM9GnONzZhmBUGU6voomA7W/WFZAqi7cDNEEzT9E7oJAoiQBNXPXngmJX8OL\n" +
                "G9yLMOTolFlLoUvmAoDGryln42gYcYXdJMoWCq+JkAaxs4tVCl+OkAfLRM7yh/IZ\n" +
                "rhjfeQpMcy01e+Oku2AqdJTQSDjDBrvI21+rB3LnjJvWbpm7NbJL35LmOc/kd2YP\n" +
                "yFw4vJ0uFdn95lKEuM6HY/PtkJNr36/qwJ0ixntXPCyYLyDSFqaSa+9LGbcJrp6y\n" +
                "RoCD4hcZOwIDAQABo4GLMIGIMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1\n" +
                "rzrJMB0GA1UdDgQWBBQyByyedF0tXSm7sXqNOxVStH1CeDAOBgNVHQ8BAf8EBAMC\n" +
                "AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDAYD\n" +
                "VR0kBAUwA4ABADANBgkqhkiG9w0BAQsFAAOCAQEAcX2vRsH1O1HQsB/7Jlf+ov4p\n" +
                "fIwfT5PAvv+p4bo+wWcumPIC1DjUk8xnOQUz3RkhQyqTbE+1OGuA1fjO0VJZ7Yev\n" +
                "KlO6MHkMYT4N5mge2ZuxMW+35ohZ23DHEHGk174QY6V8l4ICau2s1/SRajFqfRmY\n" +
                "3s8gZFo0UBX0KIcmXSu0YHfaHWXnq7bs8kCODW0qMQnlpsUtbwdlPn5jt1kbMnRk\n" +
                "rKzjruehXGm7gXC2QlHgH/MfJgpawne/n0DwPBVMs/KVuR/HRadunSuGf5Vy/rm6\n" +
                "kZ8Lnu8+sk3pfWXdwEK2tWArcVUv3wh6jROOasEQC1Ah3H0iXv/ETCv3BnBHFQ==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDiTCCAnGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBDMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTETMBEGA1UEAxMKR29vZCBz\n" +
                "dWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGAxCzAJBgNVBAYT\n" +
                "AlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTAwLgYDVQQDEydE\n" +
                "aWZmZXJlbnQgUG9saWNpZXMgRUUgQ2VydGlmaWNhdGUgVGVzdDQwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxty81j9zfbcl+YtNeRrNlpCRHCO1tJ7MZ\n" +
                "0EjEu8j64WkbvrzcPfxHeYAyzwduXLOORu3FJar1wJ+ZTJ4ay4ONqvTiOnnw/tLx\n" +
                "KFI3aQSu4SWDl/F16bL6cfelY+B+tc2J7QoMMNQLvNGShnaefeqtS2xNQeCB8Zjk\n" +
                "quY9lsQlmafVfOPxKtJA9EjnokOU9+mfnhh/ngbr24NKkT1uuRQ0Tg6sWoa7QB0V\n" +
                "S+gGV6CNGEB7pJo58cCEOu7Tsxjd3q4bhazCXf4BQCtsF/MtkyFXfdkL2D+WzYzu\n" +
                "XoEyQL/o/2SM4SU13PfhtrF0StEnRbvlNF5Hefxhd8SLPFRjf9uXAgMBAAGjazBp\n" +
                "MB8GA1UdIwQYMBaAFDIHLJ50XS1dKbuxeo07FVK0fUJ4MB0GA1UdDgQWBBSxPono\n" +
                "OMkTA43/Ahv4n1sw3dzLdjAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATACMA0GCSqGSIb3DQEBCwUAA4IBAQBiTlDMrFBwu0cpUufJeAXPXKdQ\n" +
                "ohGYFCCTW2DA/T+PsQHnvRlRizHgt9kIJI6+4lqKAKmw240r1rsVecwDBd/Y++HP\n" +
                "LGofEWvgA66DjnSOI45C7uJC01fu9Xhc4QJ3FGgDNHncsqFIJs/Bijol94PnPYjZ\n" +
                "Tf6xUYy4pAU/CMWuc+sox34TZE9KjXgQp7JbjYHRrFWNTyDoFBQKqoechN3tWGH+\n" +
                "bIRx9Ck8RT6mhkUouR2KP+d8212wOEE/6ctpFCslGXyMt7jZjcuSlYAOcRNQWhkM\n" +
                "hiRoCMkvqO1yGAHvXCo+kGeHe5flqzQdcmuEknkDmPZx8XEse+XjtR5hI7D3\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(goodSubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Different Policies Test5" {
        val policiesP2subCA2Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkjCCAnqgAwIBAgIBEjANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
                "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMEsxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRswGQYDVQQDExJQb2xp\n" +
                "Y2llcyBQMiBzdWJDQTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA\n" +
                "1Xz0YVwI3XzROYh8YMIlBawvv7A2+T/y3AJJ4+yHFGsIYWOnM7LtEfERfkeGQlSA\n" +
                "g9ad8IFH7vr1ZRl5SdgULBfmHAvEz20vdqFePL8ArM0mOuZU/pNNc7W+MgMV9SxL\n" +
                "5dpwF84+dLuqHVXtm4HNgl6Ov2KxUcAac88mC5dH2cacGFGSgeCdTlmBioRNWCNe\n" +
                "L9pTjpJ1VgopLB5ZytlScV5p+NgihrnCkRKZaxwKX292SXyTbKLCr6F6OTzbjzX+\n" +
                "qOuFUPfrJjMISRlK2K1oa7d6FN8bI0mzc1RKiyLRVc28IS8QzXcyNKoS7wAE9mBQ\n" +
                "8zTn3YfQE9ml7snMbH5PAgMBAAGjgYswgYgwHwYDVR0jBBgwFoAUWAGEJBu8K1KU\n" +
                "Sj2lEHIUUfWvOskwHQYDVR0OBBYEFBcs6gO4B3eBPWWlvzMfzHrSmPy+MA4GA1Ud\n" +
                "DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MBcGA1UdIAQQMA4wDAYKYIZIAWUD\n" +
                "AgEwAjAMBgNVHSQEBTADgAEAMA0GCSqGSIb3DQEBCwUAA4IBAQBCi5qkuqZz+Vu+\n" +
                "Up9cFMNPiH4wEsAkwBs/rDcvCv0yHjpooTNz1Ra91TjgKPnqfkFjO4j9bKQebLAo\n" +
                "lc0V4O4BP33UgG+jl1zZZVV+vRtC8c3sXDLyQXB4OmR1D9DDol8zgb+NbXn0SHPe\n" +
                "3a+qmtBultEnrDqIdKl4cgZPKDioiEyBNmORsg/qI3bmmgS4U5LG9QI1HMUmlEsU\n" +
                "Ccb7UrMih68eQ7lvITV3FRn4x+J5Eq55+gkuWTa4rgbPrjuAoTCHuzt1QH+u6kTm\n" +
                "F00F+dF0jKW90XMIXq8P7OcUvQwuNERJ0Kn1NXCpyRhNMwW3BzWLT6eRJrr9nU3v\n" +
                "Prz6Og6z\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkTCCAnmgAwIBAgIBATANBgkqhkiG9w0BAQsFADBLMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEbMBkGA1UEAxMSUG9saWNp\n" +
                "ZXMgUDIgc3ViQ0EyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowYDEL\n" +
                "MAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExMDAu\n" +
                "BgNVBAMTJ0RpZmZlcmVudCBQb2xpY2llcyBFRSBDZXJ0aWZpY2F0ZSBUZXN0NTCC\n" +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc7eW7KCq7KAlGjq9aqVs2M\n" +
                "lsnXH8C8SqOXRofpJ0M/j53afDE0ILmH4hgoaOVhxyRcpVmcC/72sVP4gSTpAHck\n" +
                "XHULhlvx5E3tUr+ki6goatM9qKTboJymwV/hmx10idGMNVWT6ejet9ji/J23RiC+\n" +
                "EQ+TxjIsAF/fWdB74H4zCvPXnxRWy1CitydVL26GH8MnekOcp4njmDmIyVWrAwUF\n" +
                "geTwAB3xHz6/7iA9C9W95xRCTtHXUHeMAIEdELouBZotgsP725TXCC+pm1tUvbZi\n" +
                "a0P2LxR9QcMgZCsDfO7t7My49fegLLaZpJqd7V6+b/2JlJeIcNrDmmrNiopd9VkC\n" +
                "AwEAAaNrMGkwHwYDVR0jBBgwFoAUFyzqA7gHd4E9ZaW/Mx/MetKY/L4wHQYDVR0O\n" +
                "BBYEFJiUy7I6Fq3xRsRaizIrMbUtUg75MA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAE\n" +
                "EDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAB+8jMz17pv82w09\n" +
                "6pJhu2R2WHjLME/wzJ5dRBzcG8tniwcSXKzravLiOVJPFIHt4K2WGHK5D06E+6yw\n" +
                "VU4BLu1lvL8jsZwsmdXishdolGNpmZEdOH8X9siOUvtxmApeVnwsyKCEsc41Y4Sr\n" +
                "itz2siDC2nNtvG+MtVGi4tbGBsAD2+COHFWGSqjc5nBG7RBTxJL9c2JpZ+Ln8udp\n" +
                "7ccOfxSrF/LgVkdPyHj+6CvO7R57WWjcBIT2UTACl9ERGGxhAIEe0T/odhaU+9P9\n" +
                "+qkb4ZxyYBAuarU8/qRGzk2lAnjv0gfnurCrRCjLwh83uF9dF/eo9SF0N9/6J1bT\n" +
                "OOZB0Ek=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(policiesP2subCA2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Overlapping Policies Test6" {
        val policiesP1234CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDwDCCAqigAwIBAgIBIzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowSjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExGjAYBgNVBAMT\n" +
                "EVBvbGljaWVzIFAxMjM0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
                "AQEA5Zswifhj2dT7WU826z9T4VZWyc4sgtEpEVLsV7AbMOMFR2ind4R/fSTyrw7e\n" +
                "szphTfev/5eBa95JdOVqxfPC5M+Cri2NIZEtTSll0ybxk/uy1UJ4s1ZTwCI0QqJw\n" +
                "m5jR4JnFsoIhfaU2xP5yGOEbh/JpKK8L4Dlm2W5AXs4BCYiqdSJsoDlG/Ay9xBzo\n" +
                "dP+u8Zv+MlNZWMKExqOQxxxvcsSuVxziTjYZggMchaLTOgUua2PifFWPm7DSVswl\n" +
                "cOKbtaIsd6ya9VLmiutIGoWEeLOcjpiM8lkx4lk0DGx8SDTzDsT1yfrj/ul76ujP\n" +
                "Lwf/GABHoLjC0Gv9yLG5699VxQIDAQABo4G1MIGyMB8GA1UdIwQYMBaAFOR9X9Fc\n" +
                "lYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBT2/amMJiy0z9bT69QerZJqHbskUDAO\n" +
                "BgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAMBgNVHSQEBTADgAEAMEEG\n" +
                "A1UdIAQ6MDgwDAYKYIZIAWUDAgEwATAMBgpghkgBZQMCATACMAwGCmCGSAFlAwIB\n" +
                "MAMwDAYKYIZIAWUDAgEwBDANBgkqhkiG9w0BAQsFAAOCAQEAPCzijaW/6TG6zZls\n" +
                "SWF2RKrsRSG7qMXa1K7EWMqkCfHw/9QGe7xCtlhQRHC4ujJqwwHblOZx1t/07jLS\n" +
                "pP2R7VjOfSoCER6a4e1ylKPsP3CrxxjxdngZ6c7JGN12MqO22d38yTuGfgYSiscJ\n" +
                "ydBXzqygLGCO9ocBscvA1l49aDo7nkbStAc010/2nFiv6xdasBNxu+DLTRyHnDUq\n" +
                "DaxJ06wsiWxRs+LpSov2m4cYPCG3/hy5LfQD9cRPPUBCSGVH77rk907LBpp5ZnAM\n" +
                "NRxyldQ9z2EbjE6Kg5ZGIx1UbpvUw36YFX6yAWUj7wUcPT1mArZq7EWZByaVWa2J\n" +
                "dNwGOg==\n" +
                "-----END CERTIFICATE-----"

        val policiesP1234subCAP123Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDsDCCApigAwIBAgIBATANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEaMBgGA1UEAxMRUG9saWNp\n" +
                "ZXMgUDEyMzQgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBRMQsw\n" +
                "CQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8G\n" +
                "A1UEAxMYUG9saWNpZXMgUDEyMzQgc3ViQ0FQMTIzMIIBIjANBgkqhkiG9w0BAQEF\n" +
                "AAOCAQ8AMIIBCgKCAQEAxonRcataWmsQBYe9Vlc/Fw8CXsaN+DAnB1XBH2YXYyPI\n" +
                "DAfebRTxQp21q6sz2LcepGnSvbnzkzsg0nfB84I+vWmI6q3L6ydRXjRtyppa5qjs\n" +
                "Zfyknor/AdboEykbvx/b5zEBUBc7Ot2nIHb/8mxhw5WnO7EVxtgxTlx5lE0SZdVt\n" +
                "uc7G6WVe7/+SXuVqYnIZkq460YcUA3GtoDCx2oYUDfb3rKK3gjOLI3nK/JslrmeN\n" +
                "A5kujM57Tl5JwAXeni4XXCDLR0aYymGlaJqyeT/3/SvddqEJkByyL92IAvsbun00\n" +
                "bjPiY5ZRBwsBSdqwtc8wNtPPsouo/HD9gsYuiec/IwIDAQABo4GZMIGWMB8GA1Ud\n" +
                "IwQYMBaAFPb9qYwmLLTP1tPr1B6tkmoduyRQMB0GA1UdDgQWBBS5qlCBpjRmUWid\n" +
                "Qu4piGrsHMh89zAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAzBgNV\n" +
                "HSAELDAqMAwGCmCGSAFlAwIBMAEwDAYKYIZIAWUDAgEwAjAMBgpghkgBZQMCATAD\n" +
                "MA0GCSqGSIb3DQEBCwUAA4IBAQAPH4fu2YUh72cgr2bFYSRtzSeoosntPN56/dcS\n" +
                "GPRl8SXABmCu/sIYFZyfRnKyTUwKPObPm0kcokAnEkkMkCd40n0m9jjIJIaSuSvi\n" +
                "NocDswcOdofQx4fK/w//iW8VevGjjhrDbNUattppOWcaHkOAA+UnycLCRPYZmNco\n" +
                "eR31JgQ3GbFQD3A9GU5TvQjZkRUbiAyc3ETO/rCuF+zqZ6FMoBMJgJj/Q6pqVyIA\n" +
                "HLCmwq9MTKuLDhSyUB8X7OBd3vHiuCR+opFSGvIYuFpsyA20Mdmni0cJSu+08BgZ\n" +
                "xGsDyQtQ14ns++kCw7xSJR+DHvOKk8LojNH6an+IbJM5Wz67\n" +
                "-----END CERTIFICATE-----"

        val policiesP1234subsubCAP123P12Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDrzCCApegAwIBAgIBATANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYUG9saWNp\n" +
                "ZXMgUDEyMzQgc3ViQ0FQMTIzMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowVzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExJzAlBgNVBAMTHlBvbGljaWVzIFAxMjM0IHN1YnN1YkNBUDEyM1AxMjCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKLo3Ua2Xvxtv8WZdDdpkpPFPN/U\n" +
                "Z2u0Tv18NRxpPcmDI2pHWeA1cHyYL477uK8uKTG4O2RjaJYV0qFuH1dHCPFVUCVC\n" +
                "i6D77CObOpIBW5HiWykfHK4mpvjavEJ9t0rOOXjBTvloIpT/WaX6J6Qc+M0I3DZj\n" +
                "D8NZzTztV8zE1VDHwcB24WASkAEIZ7+pI6yRrvJF/RJ+xFG1Bt+XmbT4N8t8Pm8n\n" +
                "pdYEhOp0tHlMBwI30pe0jBB87UAuytxircSktrSPVl6KWb46zj4kTwIazBTlEQvF\n" +
                "yXNm0eDWzqnACQo6mETSLB8GSAftaDLmKLnDvkgn3yj3lxBl/wTQ17Q8zdMCAwEA\n" +
                "AaOBizCBiDAfBgNVHSMEGDAWgBS5qlCBpjRmUWidQu4piGrsHMh89zAdBgNVHQ4E\n" +
                "FgQUTvReofkIMHtlrJLAEQss07SWBx4wDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB\n" +
                "/wQFMAMBAf8wJQYDVR0gBB4wHDAMBgpghkgBZQMCATABMAwGCmCGSAFlAwIBMAIw\n" +
                "DQYJKoZIhvcNAQELBQADggEBALy8qNbHDuf2apnfU6p0pR2HZtWwv9CjY8NlmhEZ\n" +
                "ezLvgB5yODJvjYkKNgvU6F8pCTLTDhzpnciZ95rbSmPuT6SgcVM3LA4wNhwesgnH\n" +
                "70TMBv5ArkIaYoTgizJNujAcE/yRJ0nypglb0p7Fscuj6HUSjkOJFtt9hY6JhnYm\n" +
                "sGlmy7/yB4K30tfCfwqUx+NprBFoh97jCvzFLXfC0BPVAtfl2Yzv+CjTAEL8RK+P\n" +
                "wqa4jaQKtaotLSTRtc8+Dm4Y6FYnHLLRsPHf6sONiL1RZn7w3m4srmjf0yjCfoPK\n" +
                "6WuwbFboowgs2XJXX4vtEvwuME49LwdlGo8fxbw1zt85bTI=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDsDCCApigAwIBAgIBATANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEnMCUGA1UEAxMeUG9saWNp\n" +
                "ZXMgUDEyMzQgc3Vic3ViQ0FQMTIzUDEyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIz\n" +
                "MTA4MzAwMFowYjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNh\n" +
                "dGVzIDIwMTExMjAwBgNVBAMTKU92ZXJsYXBwaW5nIFBvbGljaWVzIEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3Q2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw9FQ\n" +
                "t2aGcDvI7U42QCqMgObhOhdJlQWJSgI6EpQj0hEAvhPULpSpC3pqiRnBzmK86R7j\n" +
                "zEk9TxnGNYFqDS7xM6Mdkj+0rOKmnzVIycEFrcQLHxglYGj8PwSgtvEq/fIuebJZ\n" +
                "KEoS/jCrryVGnEUY4JWUNg4bqOGDSFTu0JBj9lSKOOH3gh+p9rJg5Hwc+Wbjb0Sy\n" +
                "8pGRGuSXsumSugGqHKoxSWfErrnTQRcls7VqJ4y8MJwlw99q3+Xa0aVOwoi3ocPM\n" +
                "mgArtDN0rHbP7+4tNcHsIjl/2WXUokGUn2/9GSW5gBIOJw3Nd6hvtOS2nlGf/qUO\n" +
                "KM8j/wjWImLGF8MjkQIDAQABo3wwejAfBgNVHSMEGDAWgBRO9F6h+Qgwe2WsksAR\n" +
                "CyzTtJYHHjAdBgNVHQ4EFgQUkrgz3HUFQnDN7aMnoK34budYbUEwFwYDVR0gBBAw\n" +
                "DjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgH2\n" +
                "MA0GCSqGSIb3DQEBCwUAA4IBAQBikCXaSOKIYSsx3TQPKgbpM0QMvbf2ios9BSNw\n" +
                "uJv8LFXz+bxFq+7x5GyTxGZ3KLgB0hypILu6M6RfRpAuH6eRJJwuXfXM6w/y2uqC\n" +
                "wqNIR5PwyWosBjqtBAUZZf6/VVU5Xd6BnpZ73jBNxxcgJ79svcw+6AFPXlcygLjY\n" +
                "dhugLPhA7BNyKmA9kxRrnp6kCLh3dI1q7Qpl55Ytz6YuyCAHe3NMdC1Ee6c27RwJ\n" +
                "GfCjDKhkCB/LSn3jbU+y/9lOSaMRSkAPKn+dkp73UpJnJzX57KJb/XE+q6R44m6h\n" +
                "FNknITUZyD5S8UuF1g929cjBj+buejxo3P1jxH9Rb1+9/REV\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(policiesP1234CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(policiesP1234subCAP123Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(policiesP1234subsubCAP123P12Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }

        var context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo))
        )
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Different Policies Test7" {
        val policiesP123subsubCAP12P1Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWUG9saWNp\n" +
                "ZXMgUDEyMyBzdWJDQVAxMjAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MFQxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
                "MSQwIgYDVQQDExtQb2xpY2llcyBQMTIzIHN1YnN1YkNBUDEyUDEwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZCOQ4P6kmZd3Oyodn6YD0UBbvotH9OTHX\n" +
                "5zHKc1eekUGMMH3CRQgj0ze8g+N44aG3T3gVc7QNXpWnywIKQ7kaBBdYUwbE2vYX\n" +
                "v3vDPK0kkR3A1r5yPAxO3fdrGSiutntn6H3HtGesSVfwTzvVijwG3RT6SfozXeLp\n" +
                "Od0+arrnmh9QJQS1xxECCul54P/LhJCJlrzqA44b1Aox41nNtQLN+ySjQxX71Wi2\n" +
                "5cxfgX7M8ZJ1AmQrQbMG+oUD8XPihZ373hbnQIHJoo/evgHpoX31Bj1wgw/ERVT6\n" +
                "dg9GWwCaV9NML0DFGPmFwvoRdMQtiGO+MLw5yRlSrspde+HLbAYJAgMBAAGjfDB6\n" +
                "MB8GA1UdIwQYMBaAFM4A2v2qk0D4wKB5rcF4zh3XJ/aeMB0GA1UdDgQWBBTkGz5G\n" +
                "t+bIqdjt0TN/BeHxXRIkwjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIly\n" +
                "f4oOX9PIzpaazE/Fp6PRRFXhCQaiSpPoUU/ndYBiLKY+6q3lCeT1NUaeO1RApaHb\n" +
                "vrV0ZSSoKMoGChHAQG5Ewdo7ypLnknAqzxcDVIkF/DtSFjtM6x7Dd1qqF+svR0ql\n" +
                "PiMct4NtcOHqtBLgmxPl6hoN050aoZovYWwQ/ZBt28khebKejAfT3lmAcW33VyKw\n" +
                "tN+J7roGNPDXfJjSSHJ8eYDkoJUGemFhDaC0dwcqE1VjW/1HC632Spx2G347p9/e\n" +
                "k0VYMAzGxTYk2nsa9zaKrLb5u5a9kFn+0tuFOdUQkoAzoptWuP1YlsWNuy4I4F3f\n" +
                "P1+O4qZj/ChYIwALJ2A=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqzCCApOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbUG9saWNp\n" +
                "ZXMgUDEyMyBzdWJzdWJDQVAxMlAxMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowYDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExMDAuBgNVBAMTJ0RpZmZlcmVudCBQb2xpY2llcyBFRSBDZXJ0aWZpY2F0\n" +
                "ZSBUZXN0NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALX5qIQqd/Uw\n" +
                "7MRg2gQjHoTe735/Mxlza2yZGICgJIvj2V7auQHGGXTgsFg1rWaJUXJMGGql2z07\n" +
                "xZa7WLruITA+1kU1BZ87zY4aifFG/WvgItXFhtDB+OT4kSEJZiNWOg8996AwuhcV\n" +
                "6w8pZ0cm7idgb/gMJ6lbeI5DN04of9ojxKbuq6JzLKLLxLQmha1XC2PqSUHOHiS3\n" +
                "yfX9hElPnrORJGjnDZ03p/l8eIb/J8s+L9osoqQ363Km837bdxuioYv42D4YHHLy\n" +
                "lBm9vTuxd7R234qTINJ7jOSg43/0DPg0gO8gMfZ12JRvy+DyP+Askl7RDGMuxTRq\n" +
                "z8moPGpV1TkCAwEAAaN8MHowHwYDVR0jBBgwFoAU5Bs+RrfmyKnY7dEzfwXh8V0S\n" +
                "JMIwHQYDVR0OBBYEFJn4esVCw8dzBLgHq2Sp4l01/p9yMA8GA1UdEwEB/wQFMAMB\n" +
                "Af8wFwYDVR0gBBAwDjAMBgpghkgBZQMCATACMA4GA1UdDwEB/wQEAwIB9jANBgkq\n" +
                "hkiG9w0BAQsFAAOCAQEAfzbl1OcrDaD7SGeIH23hl+fmPWKKJhbP6QUM9NRGHVIr\n" +
                "FaxxdfvL1YJrU5Y4zcqK0O2pYespDfNRJOFJMVAoOzwWrhi4f9lkZIiEaUyIppXP\n" +
                "mDpI2UQeru/mvOrMvuvd9/FeKi2KtqyxNHCJgj3Z9pdYPUv3pad7cdIILVV3jRbz\n" +
                "YPS4WguwQhCEEw3ft9D+B2PXMSPhvEBNfAUC0xan6yODR1XjgIihkLuiQe/80Bql\n" +
                "d5EX0ib/SO9JK/7ybfssFcmxzjas+0geZyg2gDP4H1J1PBoZLw6SXTJ4DO6CIud0\n" +
                "EhNY3lZQpWUlN7CXlAJiqiQ4tPDto9XZcQJ4S2nHJQ==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(policiesP123CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(policiesP123subCAP12Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(policiesP123subsubCAP12P1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Different Policies Test8" {
        val policiesP12subCAP1Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjDCCAnSgAwIBAgIBATANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEYMBYGA1UEAxMPUG9saWNp\n" +
                "ZXMgUDEyIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTTELMAkG\n" +
                "A1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHTAbBgNV\n" +
                "BAMTFFBvbGljaWVzIFAxMiBzdWJDQVAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEAw442fdRTg6Jv+ElCoFqKteS7oejZSQ2gkdvxjcCLHsujyZxb1Uoy\n" +
                "vAnay9r6w6qOTgsJ4I1YO0XSRJo69S84jF2Y1/M8CdYS/cCIFVLaB8dOFz+c54LM\n" +
                "gVkNJQGCDJJYmGWWVIvs/yEPX8wIticxl6EVBq/UYhHHq1bvcHi8N2g/uzn1LHWY\n" +
                "rW2kPkXNbPkA0yUR07+sN4yL+xdi4Lp7IWAYqFgtW9gsQDigqeiAS33gTs0njsdZ\n" +
                "6omNaJpuKil5y7ml94/8QJ5iJ4V1MFynga6h7fObSMvW8xe+CQY3TPdUe27z4Jf1\n" +
                "O+ndMFxWgv3rskq5nTsX7lTKjKmGOHB8lQIDAQABo3wwejAfBgNVHSMEGDAWgBTY\n" +
                "XzXimsE3KibOg8xzDnAVKjriMTAdBgNVHQ4EFgQUIp7XDrhIzgkOOl2+1k1YI1aN\n" +
                "y9YwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNV\n" +
                "HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBQYlzL2nonRz75w9lngMPR\n" +
                "kh+gIpr+MuOWEaWVYdYv61En2N4HIYxum4dXM/lobJlD3LtNfAwY5MLSld/7xpRG\n" +
                "/KGJ5VEOg4f5J8cnBoBSCHKJfm+udg1wYz4nsIpsoCoUueLLnaIsJNSIVH/OrcGx\n" +
                "wcWdKax5udzVGm7v+IKMyn3+S1By3VUACGY8XyGtzeQB4cR2QrhRhoxyUJ/Wthfr\n" +
                "F5Ust1dUVtCNIZ8BJMEcSTvAsnjzNbmHudj0/DiAuXMF4C3uvUncoZsFoKw+VT3o\n" +
                "FBsLX1QVPwaeXRvzkJu7vJyZBaWxvm5igkpqCni36UY+oa7OlKzLny7JNGg0ZJ5d\n" +
                "-----END CERTIFICATE-----"

        val policiesP12subsubCAP1P2Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDljCCAn6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUUG9saWNp\n" +
                "ZXMgUDEyIHN1YkNBUDEwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBS\n" +
                "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEi\n" +
                "MCAGA1UEAxMZUG9saWNpZXMgUDEyIHN1YnN1YkNBUDFQMjCCASIwDQYJKoZIhvcN\n" +
                "AQEBBQADggEPADCCAQoCggEBALcO073fv8c5JQbdcjDww0pNGK2g+usBAvTQmcWh\n" +
                "Z3JhRdupod8gbYrEkMWebubmwz0qpdnMT9DN98KvBxnvzT1qUqAGv3XcUjLGg1mp\n" +
                "AaTvkmSxHmABma74QKv9v/D8VfvHG5kzJU0HPlnJZy9yVTZs5pqdpKdE/8SkmtNj\n" +
                "0fM96XXKpmprpuCzlhvujpi+3SQSbrXFK2cFgcXHsRp+chRmb3bLhg2W+cyU+Fl+\n" +
                "YUMr24pljeGGZfPkTEmjXBxGsC8hYjwVWAp6Mpf0UavA9esKTJcsFHn3rMnbBZvx\n" +
                "vgmV1YNRBo+CmUmH8QWceZ3AthN43SXUPsFDmTa5ThAXwskCAwEAAaN8MHowHwYD\n" +
                "VR0jBBgwFoAUIp7XDrhIzgkOOl2+1k1YI1aNy9YwHQYDVR0OBBYEFMelN6fQ+iTl\n" +
                "fN/b8l1p2+7K9pnuMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MBcG\n" +
                "A1UdIAQQMA4wDAYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsFAAOCAQEAS79LmgcD\n" +
                "s1pCo0RLnthY6dTlCGa1z1TVOERBuf5VWC4mO6UdMZp1ahIegjocC5KJzypNyT6k\n" +
                "IGSP6NeBN9rDF1smYx1M24mdV0xzQlEG1lcY6fetIvaC/U9i9nAIqRZStNMA59gW\n" +
                "4LH1ctSlRIoErJFR/DsKkDO0LumnvCE79qs2PikXuJFPj/tD+KnSFNhZkCL4UJKm\n" +
                "X7g0gXh0y0XQQUqzqwP/VoitGZJZ8ZeNvnQTfeMaS8z4+2bIMzdQN8AyVtSpWtnZ\n" +
                "05VTmnYBCfFjx5z3f1srHvG84jzAedaN1Kpnebds3wvLW2ud8J/3t/mlLNmgHWFD\n" +
                "jXYibav3P+Q6Dw==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqTCCApGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZUG9saWNp\n" +
                "ZXMgUDEyIHN1YnN1YkNBUDFQMjAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMGAxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMTAwLgYDVQQDEydEaWZmZXJlbnQgUG9saWNpZXMgRUUgQ2VydGlmaWNhdGUg\n" +
                "VGVzdDgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBmcAEklgPYV1v\n" +
                "LOS3HNnWEIU4xixNfJqIAwV8nqXrQx7a0eymXeQ7ijyCkGPTOG+X5SHl7MT1EYun\n" +
                "ASdRHbAgauU8IMhcG3a9GW6cP1uT04cHpS5WJ9SU71MDPRmLN9YorypgZP3ZxqIm\n" +
                "Jp4g1KWYqwqegJ26wu+8JpmFFhj79MYGRmbM9TisxgPZP0kyJroYcSrdNJMXOXaU\n" +
                "bmsJpQwwuzuDn4NtH+nTpaHx7ab2BKyqKYKyxkFLmr84YbD9Hqa9/czLJGF0Tf+u\n" +
                "IUwenhHylbsWRlHirRA0FqHagTIl1O9+ptNsYcQGtYKE4mqMtRohd3GMgKqJx7IK\n" +
                "yjG9uSWHAgMBAAGjfDB6MB8GA1UdIwQYMBaAFMelN6fQ+iTlfN/b8l1p2+7K9pnu\n" +
                "MB0GA1UdDgQWBBQXoW+qF2xTgQ0UHV2q7B8e9Jbn9DAPBgNVHRMBAf8EBTADAQH/\n" +
                "MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwAjAOBgNVHQ8BAf8EBAMCAfYwDQYJKoZI\n" +
                "hvcNAQELBQADggEBAASApMwfhokiI14ONWgsD8Q0fVCOMZAHpFBEFWWsI7FPtyPR\n" +
                "sLVIdpHCBg1CqlW8hM9EMOa8IGBlN/rfsX/EbWFtOTUD5VNXG7HD9qfexVdddf01\n" +
                "hqyLKW6IQUZdiGy8ljN2nuLN5kjrv6EaAYbbcrfgkrSiB1dNMvSG0ZCZfALNXAl8\n" +
                "5ny4g1l6uvzGmb6k3O6F6s1NOMpJuUpHlgZ9Ggd6NZG61vpYDSMHzknfduvzbHhy\n" +
                "r5A57ceLPfJrCzdGXNhKhtIrq63zfkIFCC8MygAWcySXN3HtxcHu7QTz4M3rVID6\n" +
                "tVUg+PqT+oteuGr6tqeJpZwM4xZk9VabHaVr4i0=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(policiesP12CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(policiesP12subCAP1Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(policiesP12subsubCAP1P2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Different Policies Test9" {
        val policiesP123subsubCAP12P2Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWUG9saWNp\n" +
                "ZXMgUDEyMyBzdWJDQVAxMjAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MFQxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
                "MSQwIgYDVQQDExtQb2xpY2llcyBQMTIzIHN1YnN1YkNBUDEyUDIwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu2XI0p6/0X+8rTP8FMrqJKjFC2fDJHzer\n" +
                "MYV5HGjBMbMVJS1+V+mjNrjefbErnD4OlZ6de+ckdTZBMwn7YYcNw0W2YAX8gnXZ\n" +
                "GRZLEjGbqvVJFXpHsjrwNdftP3k4MnmnvgeMJ3T1bmUFiwStmf9BA/qWpmxblo1Q\n" +
                "C73IKSRfvOQrKm2x1t9niuBiDFBsEGuGbW+oGMyV6dBgrAfEv5r4RIqbcybqBWWI\n" +
                "1V2BVFPRQGpIw9IVo3nKY9JU0fPR+m3gB1RozpHVvuHBEyAFG+6QLztmWVcrPXZj\n" +
                "PC0X+q3JMhE3O3N2CqeeqBRCzJCd2hsN86rJztJjJzhZiM4aXChFAgMBAAGjfDB6\n" +
                "MB8GA1UdIwQYMBaAFM4A2v2qk0D4wKB5rcF4zh3XJ/aeMB0GA1UdDgQWBBTp/LZe\n" +
                "VhROBh3RMv2IYGsQ+AUbaTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB\n" +
                "/zAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAIwDQYJKoZIhvcNAQELBQADggEBAE2c\n" +
                "iEnVpboWIBLYhAY+KzMng7Bo142+HWiVSgn+7nLEXXODv80Y0OgvVplxliiO1D/s\n" +
                "vCBHuFb84tWG5aIo0tZwir7dGsmiXxUvDBVySLbfftJZWK+NpcpBif1s0E5NOaR0\n" +
                "Tj0wutAl05tSoZIH8AjZrBVsLiUt0HfYKs4ntAvcJC7CbTPMG3/8NWmWvOcfWLle\n" +
                "sJUomwPMw6990m4lPLAGiKnYEbb8sy8FTmLdzLuI/Pxgj4n04J9/KRJW57dz42ea\n" +
                "MfJI9M2gG77kMk0UqmPp2U/6nJkhPfiw3OXDQ+pOvHHG6UFYw99dxgT7o0RDAJHQ\n" +
                "vAf808JCcAlN+EN/7kU=\n" +
                "-----END CERTIFICATE-----"

        val policiesP123subsubsubCAP12P2P1Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpDCCAoygAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbUG9saWNp\n" +
                "ZXMgUDEyMyBzdWJzdWJDQVAxMlAyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowWTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExKTAnBgNVBAMTIFBvbGljaWVzIFAxMjMgc3Vic3Vic3ViQ0FQMTJQMlAx\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo9X8Ddrh9jmdsYRFm28y\n" +
                "92U7sqI995aXi5l+dZtIFpZebhYISF1OlBVv830ZcKZgW/npnqbTX4irRR/Si26j\n" +
                "w3Z9DECHDLWGnAee+O/5wRNuSlbJzfnJfe+rNCPuy0vcAJhAfz6RmueuwyEdy5Ss\n" +
                "isw92sb0e/UfqKq1ReyTpHh3Q8VDXse5kph0A753UY/1ZBZbPD7/Q/LYrRRnDhLr\n" +
                "SVUOg6Mlfu93+jsuwFgcB8VIkd9rdbFIkuxS196/VqtycM+KYRlfYz9N3dSUJhzQ\n" +
                "pL+xYfC7FRySc63BVFRwWYXd8/vmyrwpoGd8657RRp2/e4gp1avZZ5A4mYoPQ3Pl\n" +
                "kQIDAQABo3wwejAfBgNVHSMEGDAWgBTp/LZeVhROBh3RMv2IYGsQ+AUbaTAdBgNV\n" +
                "HQ4EFgQUiSAXhPusuwnX3l5enmj2OVAfQIgwDgYDVR0PAQH/BAQDAgEGMBcGA1Ud\n" +
                "IAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB\n" +
                "CwUAA4IBAQBzP6juBoRYCOz8FzuCovzw5TK/XNmUtWAVYOH3mqjqpP0BECuSVbuZ\n" +
                "BaSFm8IoFE26babq9OQ+W6YzZd2hcJOAQQA6yLHs20Es3sYk+sWpduSgLNDpf6CE\n" +
                "7PFzgvQ1vwnuTANNlNLQcoNQrA5OYD1bNLnmZlvenAidbNbWDORDTiyL86Bc1JF7\n" +
                "gKJFTet6SFKnVugZKWz0qcexhJtdTW6dPS7yZ1/HJlc66/KGPvD3Lxanz/qY5ZP1\n" +
                "lg/32kPI1xOtoh+sL23f7iE/g/UHY6+yC4Ot4ufgH9j2wdAVhkclavvn4y9yd3b+\n" +
                "nHGboqWnBZgQOPY33l7TvzvZC7bKpT5O\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnzCCAoegAwIBAgIBATANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEpMCcGA1UEAxMgUG9saWNp\n" +
                "ZXMgUDEyMyBzdWJzdWJzdWJDQVAxMlAyUDEwHhcNMTAwMTAxMDgzMDAwWhcNMzAx\n" +
                "MjMxMDgzMDAwWjBgMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZp\n" +
                "Y2F0ZXMgMjAxMTEwMC4GA1UEAxMnRGlmZmVyZW50IFBvbGljaWVzIEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3Q5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvves\n" +
                "edFLgv8vlu0sxCTplwV97n0bNnx9po9ihH5BWII4NuhB1SG566w+qeo+LxlUDCr7\n" +
                "SF3lwgxIvo+PaKcNP7SIiFEt++kSyhk8DjX5qKNZjPWDNWDDD6ZJBTLAl9YGlUdY\n" +
                "knJdMBfjmsCQ0BP66ip203PSnQTCuhLdRN/syXTP5GC7MejAmILFCyIddxBi9wwd\n" +
                "nDNMKNl4qhwcYdU8gCAB52ERHJ/WFJ9fSGkVWus81ViI5FaWblGC33EgUm8jqFX4\n" +
                "hlvygwD4Q/9bjVVJefDXXXJ6uStLrY+K6Vf8rwtTLneOo51ZE3QMfkL2VqR9sB1v\n" +
                "8Yx4HcOez04D3XiIvQIDAQABo2swaTAfBgNVHSMEGDAWgBSJIBeE+6y7CdfeXl6e\n" +
                "aPY5UB9AiDAdBgNVHQ4EFgQU4wZXd/NUEr4ONS0cVpjBz6mlU+gwDgYDVR0PAQH/\n" +
                "BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG9w0BAQsFAAOC\n" +
                "AQEAO8XGc+e+gxRvjmGI9a7myCl3mhrS9UuU+yid6C6u+C00it+ummR7SeHikTDJ\n" +
                "j4VGXGpsaIRTPg0O+ddfegXB+WsQ8Rls4dpjUz7RLfMZFVvr7vWBMBDSZjQPYieE\n" +
                "BYvzK0boQRrTeAchP06/SOl9JHfFuYm/YOqvgofTJaG1SiEULCdC3kqhU6V5rY1w\n" +
                "oJPvgmBOyw0Cudj4H2zdLlcWqF0wl9Tc+BECqyJe+A4WW1nbrCmS98aHtLOnWlSI\n" +
                "nAfWDY6emd7hja7EuJdNqWVenkX/mske6yMlH7PNNEhMjeNVQMt9YlLNb+A7i/XP\n" +
                "+W/k74kCn3JDwq9dfLK1kya+xQ==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(policiesP123CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(policiesP123subCAP12Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(policiesP123subsubCAP12P2Cert).getOrThrow()
        val subSubSubCa =
            X509Certificate.decodeFromPem(policiesP123subsubsubCAP12P2P1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "All Certificates Same Policies Test10" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqTCCApGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEYMBYGA1UEAxMPUG9saWNp\n" +
                "ZXMgUDEyIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowbTELMAkG\n" +
                "A1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExPTA7BgNV\n" +
                "BAMTNEFsbCBDZXJ0aWZpY2F0ZXMgU2FtZSBQb2xpY2llcyBFRSBDZXJ0aWZpY2F0\n" +
                "ZSBUZXN0MTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQIvsOjHjY\n" +
                "csCDpWm9SJNK2Lwz8/4bpvlcdaG59lROqyk6OL+0/Rd214G74S26m6BrgZuzoLbH\n" +
                "MlAaCjdFDbUSjh086jFDMgXHwdud78f442+V3ms02gqmijFPvSsOWWyRu0BzTz0P\n" +
                "bW9IWYtIAG8DDqGflBISatXkxS8wQHCuZdY/x+XjjISn7oSOjPamfdoqT5jEThof\n" +
                "50jzBxDEdW1vbjU4afAwQBD28t6fZCdCG5kUO1uZ3CED0R44ZV0gajS1Oah9qvrH\n" +
                "jeCFGGRmoi1biVzNqe9N9tyqw4PWZ+TnzANsaf+InI09mZGyPoiQXB6mbfJFnuCD\n" +
                "ZQ7AcQiP1VPbAgMBAAGjeTB3MB8GA1UdIwQYMBaAFNhfNeKawTcqJs6DzHMOcBUq\n" +
                "OuIxMB0GA1UdDgQWBBQKlt4EYF5FmsVHFjO1gRk49P4KtzAOBgNVHQ8BAf8EBAMC\n" +
                "BPAwJQYDVR0gBB4wHDAMBgpghkgBZQMCATABMAwGCmCGSAFlAwIBMAIwDQYJKoZI\n" +
                "hvcNAQELBQADggEBACu8kiAp80ujcBGHavjXgp+HpVSQTqRzTLKbf0EFFib6KedE\n" +
                "sT67cvLjuTZMcPmwYHnUjBk/KGdyn9IwetblMTj3hueKNx1yKXfYYNVmE13KPPpN\n" +
                "NcPe4Eal9g4I2noPVt8Eg3SgNIghPFz3XJQNGjN5hMdhmcQfeaEJe1Mlwv2cdgs3\n" +
                "D02kpjI/KGca9whyDpE0jpu77gkO4ZmRXZxaGe8i35xaRrrs124Zhz0qtJn7iIaV\n" +
                "s7ouezKkvE1UinCY2pdTZHMTs8LSklBE/IL0Ojwqpt81FptUFMihOaMtMrg01E/D\n" +
                "rahtaL5Nbj8nVUGlVwiEkUy1CII3ALs50xqw8gM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(policiesP12CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }

        var context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }
    }

    "All Certificates AnyPolicy Test11" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjjCCAnagAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMYW55UG9s\n" +
                "aWN5IENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowaTELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExOTA3BgNVBAMT\n" +
                "MEFsbCBDZXJ0aWZpY2F0ZXMgYW55UG9saWN5IEVFIENlcnRpZmljYXRlIFRlc3Qx\n" +
                "MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKLRwAzuUEtOy/V47M/\n" +
                "rUpbPiMDRXuhXbrcDN+erHgrUrGHJA5FpjmB6PRYL7fR1mJl+yGRCDrquNaHkEoi\n" +
                "iUVGpuC59jBUIguJr46ZPrAg4XYzWe/Wh8JTCDubDKEVlbN5F3c+ih8N8aKxQpGW\n" +
                "ZPm/CWaMljKSBgZeyFzDN4lrAvQYfFeR5yvRQ1rZbQPi3mLjUHG0JwsaCbPYSv3y\n" +
                "v8XSye1NENSaPaDQ9H/CzLfUKldvkNCnZmeFaI6UKkaqr7RMvqymdIpSjz/Ic7fR\n" +
                "96ZZgQzCX3EPZ5k4qyaTDgvuLCvlMrYVmHRy3oj8XHkb0VP1zEFmVYyx8gM1UBk0\n" +
                "HKkCAwEAAaNlMGMwHwYDVR0jBBgwFoAUu8neyByV50LikKKOrgNcqyRgfoUwHQYD\n" +
                "VR0OBBYEFP0x7qhv8jhIP4wDRMsNB2Ztq9jpMA4GA1UdDwEB/wQEAwIE8DARBgNV\n" +
                "HSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQELBQADggEBAGpQqQ5cWZS64sgYSqdC\n" +
                "NW7g6xU43pbHIqs0NxBefMaYoHRcnBZKZZ51mesxhLHBqOQmJZfEGmUVDJvdOfDD\n" +
                "N2ShmiO9sZhVqkPZ+PMu3M1hNcnuhyNO7XnlmKKzWXApasvMivL9qM6ZNa0yHELY\n" +
                "2sgKEo3y/pL4Pxld5usNH+dBib7FrhEvCZzgOKZcfC6ZQskkVDiduhtPlRM8FRtl\n" +
                "wlrWwLPEPMrYe9rtqGozEOKS7HP8SWI2zzkhIZK5dVXYUpJ+oRAYtLmKuiIAJ+PY\n" +
                "hWFAwNYtyafe1P164tjeT/JtHAGPQ5ogzcelmzRk8UDG+G/V/MW9wqQTCDzkCR1c\n" +
                "Fmo=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(anyPolicyCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }

        val context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }
    }

    "Different Policies Test12" {
        val policiesP3CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkzCCAnugAwIBAgIBJzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFzAVBgNVBAMT\n" +
                "DlBvbGljaWVzIFAzIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n" +
                "4HTZ2qzQpYWTz2Y6/AOG/uDqyc7uIc/bltDD0h+0g3c2Y1cK2couvrTwShS8gxcj\n" +
                "2va9m9EdMuex5Qk0kiekGoKNmWokKAKxTmVeU8fAgcPz7NJxLjsF4YX7CVVeB4+J\n" +
                "YeOwT9i+4D7qQ0JjZfmZCqxJIqWKpW/U1C43QwMh2TvJ3EIAFwLpHqQpZanugNJZ\n" +
                "Ljf5Jpntjn1dLFAvk086cx37dNn1nsFzy4pOpzSfMYK20rHK0VGtyTHc3AMR4mjm\n" +
                "q2SOv5Xrnx2uI41HNxk5BHvX745TwS3sUBMWRTw2G8DMXTy1HonZxVc84GWDW+04\n" +
                "RSpgPoh99Inz8xPTTNOTgwIDAQABo4GLMIGIMB8GA1UdIwQYMBaAFOR9X9FclYYI\n" +
                "LAWuvnW2ZafZXahmMB0GA1UdDgQWBBTYBassoIvDktzGrWo/v/PGmOXc/TAOBgNV\n" +
                "HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAMBgNVHSQEBTADgAEAMBcGA1Ud\n" +
                "IAQQMA4wDAYKYIZIAWUDAgEwAzANBgkqhkiG9w0BAQsFAAOCAQEAXXC8Q5AzwLws\n" +
                "Cynt11pa7Nl4I15DzEd661tWYavZj5o0OH+dKdu8kGRaH5fJi4th1oWdJ5V+y7OF\n" +
                "XivnxP6fZMZy0CJhLZhoCm1O7y6BsM4PMOFRgZ7kPNgoKTaT9tMmGXTJDsG+x9ph\n" +
                "/Ro4xL/ZAdREO+fN0r2LmyTZ8zud1D8mV4yrWA0+HLj6MoPe74w5JRnjI1bLp/pX\n" +
                "6Rw5EwoYNKrKjMp1VutAEY2ZSdKgdzP1tVnMn0WsluxuzQbLMZ/Zzu8U+HEGsBPv\n" +
                "nYWynisQlZsxqlz4dLqD1FuXv12GExxQSr1AbBJDGcZZg2D/QbDXT39lYKnjRl+U\n" +
                "J9DHk++AHg==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjjCCAnagAwIBAgIBATANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEXMBUGA1UEAxMOUG9saWNp\n" +
                "ZXMgUDMgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBhMQswCQYD\n" +
                "VQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTExMC8GA1UE\n" +
                "AxMoRGlmZmVyZW50IFBvbGljaWVzIEVFIENlcnRpZmljYXRlIFRlc3QxMjCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPN0T7wjQBhGUgt53voETJXwpFYH\n" +
                "7LSwR966p1DkDY/sTYGE7D/xxxxrz8FP0BPUvcAncfBKwBkEJ0ioEc7Wjgz9vnaJ\n" +
                "o+tzJxiC3Ez1aRXEcEUNCYybApVy4hWAoKBqFp3sSZJjrZ97hzYkihCJEkTewMDg\n" +
                "nE7Ru8WTt1JjSaplKZ5OajYdhdLGvESIOpFGMEbA4RlptpHeUjN8TU5a2E18vHfP\n" +
                "yOs5tZzD3H9ZnmdKosn6RswkMO2W7gMO+nmvo4BfDnpmXgwMzBzDVoS+rW7MGVwP\n" +
                "eMNNVz7h9UYlBYhRDSceAjF8DThevpzMAYfr4+g1lmdxmVT0ATXZ1OYl6FECAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAU2AWrLKCLw5Lcxq1qP7/zxpjl3P0wHQYDVR0OBBYE\n" +
                "FMNvgVWsNk7EWKBgwL8ilshd+5PVMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAQwDQYJKoZIhvcNAQELBQADggEBAKMG4iNWYroyty8c3qaz\n" +
                "37GdWGbiDQEhIQ6xJqxykoNZoi7D+ixkbH4OxT3pGB407ig84zH6rSHTgUrGh+gZ\n" +
                "nrNWzDJY1qUc6NDcmH4VkoX0XpGoxqcWe3F9WV9HA1ZHY24Oa9wPTg3Srjdg9V7/\n" +
                "eMe8KiObAMGy19rgrmiPX1NrhsYL+E79qfp9UpjwrSr4YWwQo8vzxwFxClAdFbK0\n" +
                "eeNxr8/kn4+9Q8+z2R9L7NMpKU4nSsZdozcJBqPsmRRKDjbBxKQg1defVscbp0Wk\n" +
                "i8eOL7EJYT0oljx5QMQ1o3HUDzsYGQ84MfJ7fCkLcT2kQpRR9cF743q0CZMYl4JA\n" +
                "XTo=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(policiesP3CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "All Certificates Same Policies Test13" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDujCCAqKgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBJMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEZMBcGA1UEAxMQUG9saWNp\n" +
                "ZXMgUDEyMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMG0xCzAJ\n" +
                "BgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMT0wOwYD\n" +
                "VQQDEzRBbGwgQ2VydGlmaWNhdGVzIFNhbWUgUG9saWNpZXMgRUUgQ2VydGlmaWNh\n" +
                "dGUgVGVzdDEzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuonnfN9t\n" +
                "4ddPZ+ia26RVmETsLKghhyuChxjPOzey0QTTUvM7qpHFYdIxV33GrQo6A7gFqhHd\n" +
                "fWyAk0/BneTtf7NMzEVpBhgN/ALibFRF+gtg+9+PRECBOBTE4/Fn3NTVei0br+vY\n" +
                "IHq3/S1YmJfbaT75IMLxJLevjBaIEg1ZAC8e42BydhD6yOvclRCtQaTmlVMPAF2w\n" +
                "16xXisHhOlIdkmoTvVUNsggM7sfp3Mh7rdUsUgZTdx7lN7COEYIo+i3IU8YqOfeo\n" +
                "nonwyxPR9p+vHCCau0445QquJxq6BBiIIFBqyEKPbw2y0a5tXWu9HAqkWSZD+1oJ\n" +
                "y15//w8dWuiHwwIDAQABo4GIMIGFMB8GA1UdIwQYMBaAFIwoCtoNCRRi7j09lrhx\n" +
                "kxKJ6uhjMB0GA1UdDgQWBBQV5I2I9FFatmEJLjYrRhl3ENmoajAOBgNVHQ8BAf8E\n" +
                "BAMCBPAwMwYDVR0gBCwwKjAMBgpghkgBZQMCATABMAwGCmCGSAFlAwIBMAIwDAYK\n" +
                "YIZIAWUDAgEwAzANBgkqhkiG9w0BAQsFAAOCAQEAebUg/2b+Scy+m8LoFzpVGpLL\n" +
                "81MsDH+Ft+90ub0m3BPmLhy6M+pL6I3w4roiOqdnbokcNWiUKLV+0aGR0T+fLw7H\n" +
                "mhltaORuZHTZAPZq3X1GwRS80r7kPBJDCmT5sf0DrxMg9e0tpJSKu3UQrONk8DyH\n" +
                "z64u6w4tlg702fdr2VZv4VLlUtLkx2cMPwMK+ZKJ+FBK07z/69EroGdakfaJqMA8\n" +
                "SW+VOyqg+koUo35DUv1n/t8/DaE7rNux298Ii1JZj8umtVmIet4sHBuIf5Y4nmYD\n" +
                "KJxml+xOmIJ2jXfAb0A0VmpGg4SYCcUTH4gWKA7oPAYnic4llcUeM71RGKzuoA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(policiesP123CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        var context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyThree))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }
    }

    "AnyPolicy Test14" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMYW55UG9s\n" +
                "aWN5IENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowWDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExKDAmBgNVBAMT\n" +
                "H2FueVBvbGljeSBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTQwggEiMA0GCSqGSIb3DQEB\n" +
                "AQUAA4IBDwAwggEKAoIBAQDKV4x9YSxioiuPeQ7ngd0MdwlQUnIwpX/DTeU+Zjxw\n" +
                "UXS4MzHRn8zuzbGP7DfS6lmx9RMpFE0UV+zyo6/iXaeGgSYIoDoP+mX+o2Fy1ctK\n" +
                "sJjDmq42VSs4OOKsYGm4kVvLhRI3xPdj/OzB38aukiJgBpyBa6d/y9RoTSdRibE1\n" +
                "yjgI7GeZq1Oe8L6U4JwHTDG4HXZe1cHYROPtr0favOsOsROEvScIOG6nzNtcdCgy\n" +
                "yHcRODBMqI7huxuQdgdUDk1oc7upF6H/RHLIWnIYPTT7zR1J5+6LEt4OG9jKB2/X\n" +
                "M8FbTR0OYcg5gpAHMNfWozYLLolyNdo/PUz8os9N9T9BAgMBAAGjazBpMB8GA1Ud\n" +
                "IwQYMBaAFLvJ3sgcledC4pCijq4DXKskYH6FMB0GA1UdDgQWBBSxz2HJeKGhgtmf\n" +
                "nkgFMNb1Oc+6ZzAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMC\n" +
                "ATABMA0GCSqGSIb3DQEBCwUAA4IBAQBPBpWPbfq2YB7SyxdRFRsYl0Y88JvLRKme\n" +
                "jmCrJlUPetIxVd64HNJrcrguqsXM/iWn+U4Z3lyNS0gGDUkazuKi5yoWonFqdrzg\n" +
                "z9e7c7HY9NoLfb0c3dNmfll9ZGLB977XFWOIPj7Nwrfaoge6LvjyUT/hT1QqZ1aX\n" +
                "2DOGOwucC6HoO1S3uDQuWDO5ZvVrLLP9oydpd3nfHtBu1S04qG1fZ0A58YYLhT1k\n" +
                "+IiZX35xhNtNDKbiCQPu6uYeN5zABQuL+e5SjDujOPVHJDeHphAGLgpbFIu5+NkO\n" +
                "SXbxdzrX+dllyieqlkyWIuEPHWa9SSNRRUv1kQSqd9ON+iL7DilL\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(anyPolicyCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        var context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne))
        )
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo))
        )
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

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

        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(defaultContext)
            validationResult.rootPolicyNode?.getAllSubtreeQualifiers()?.size shouldBe 1
        }
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

        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(defaultContext)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }
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

        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(defaultContext)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid == KnownOIDs.anyPolicy } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }
    }

    "User Notice Qualifier Test18" {
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
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne))
        )
        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(context)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }

        context = CertificateValidationContext(
            trustAnchors = setOf(trustAnchor),
            initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo))
        )
        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(context)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid == KnownOIDs.anyPolicy } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }
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

        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(defaultContext)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }
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
            explicitPolicyRequired = true
        )
        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(context)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.CPSUri
            val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.CPSUri
            displayedQualifier.uri.value shouldBe expectedQualifier.uri.value
        }
    }
})