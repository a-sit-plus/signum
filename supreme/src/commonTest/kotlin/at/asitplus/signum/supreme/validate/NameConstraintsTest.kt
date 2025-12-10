package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.validate.NameConstraintsValidator
import de.infix.testBalloon.framework.core.testSuite
import at.asitplus.testballoon.invoke
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

/**
 * PKITS 4.13 Name Constraints
 */
@OptIn(ExperimentalPkiApi::class)
val NameConstraintsTest by testSuite {

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
    val defaultContext = CertificateValidationContext(trustAnchors = setOf(trustAnchor))

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

    val nameConstraintsDN3CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID7DCCAtSgAwIBAgIBQDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTzELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHzAdBgNVBAMT\n" +
            "Fm5hbWVDb25zdHJhaW50cyBETjMgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
            "ggEKAoIBAQDGcxuyIPM2Ih2s0FbK8O1gDt0zWIuExMS6mU7Sy+BgUCD9qstR/BNv\n" +
            "8YYUtepUZyztqonXiNY1STW4FjumzN3+izaIH+9Ji6sLrc3F7U+G/N0mzungENbI\n" +
            "HzE8xMOzNiChVZOXQuU8S6OhYn9gQBRm/xCJlwPSaymBQz2b6j/hwQJjzQG/pwWb\n" +
            "hYhDU64Lf4kDJ0MENkc8wlcyUj2dHEfc9jq49W/5FcG7Gyhb8XUGQAasV8mnc+Aj\n" +
            "hKwliqg8HA6Um8yXpRuKBv1pSvq5ZwnE0oWSntnHKjcQHvRkn8JCIE0JYaLwwx7Y\n" +
            "ZSCWux3o/bGAEE7uZdS354a4MUzK6PqbAgMBAAGjgdwwgdkwHwYDVR0jBBgwFoAU\n" +
            "5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFAbcW77HEjdZpIpAdHwJnUU8\n" +
            "SqHbMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYD\n" +
            "VR0TAQH/BAUwAwEB/zBdBgNVHR4BAf8EUzBRoU8wTaRLMEkxCzAJBgNVBAYTAlVT\n" +
            "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRkwFwYDVQQLExBleGNs\n" +
            "dWRlZFN1YnRyZWUxMA0GCSqGSIb3DQEBCwUAA4IBAQCATlxJGDbeYJueWqOhiixA\n" +
            "PfOIc2ZXmtoWkeJv2l8Eyoy3LubjUgrpZA62jOvj+0irrrC+Vd32gO8pQ7NYBwpm\n" +
            "gBqRgbCKhPH7U1Igblj2twEZozkMC0BO8YLfzXngKOIb7BJuuhG8KCMVPVtu9/Xd\n" +
            "Abov5aS8tJh0cKfi3d/eu8XpYsPtPQkwodpKSHHXFZTJlYocJkVGdDIO7cb/WfPj\n" +
            "pVDkpZdRiX37Rlk7CBH+YddypFZhEnGm9e1bgKmF2xgB0MXMfWndev7XSO7m+KkP\n" +
            "h4yxFJk8XE+erQQQGxWc1RMEsXTppijRrrpqirF5vDFseW9U8C+VE0VtFxFkxlqn\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsDN4CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEQTCCAymgAwIBAgIBQTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTzELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHzAdBgNVBAMT\n" +
            "Fm5hbWVDb25zdHJhaW50cyBETjQgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
            "ggEKAoIBAQDErlH+siiNuSte+3eQGs7cT2LBjfndbDv/SSKvazHDGHl3jg/m8OF5\n" +
            "650gFQ/vi4HVN8IXfICMNpWL7XKTvpwyFydsPi5DiabbrdL5lQqugKDxVt4o0AJ0\n" +
            "IcEzji7w0syAaJoCXmX8inM4NVwDKuwk+3PYFBygOPn3C690tVHVq6Y8eesqsPam\n" +
            "d33HZNpq26KLEkIFvGQPHO7q2jPGgvXH6X2njhewKzy1iorJgH8fYA3b6XtdqLZF\n" +
            "OstCkz8l/iNTBab+jQSB4bdwuaA03QaCaUp6VB8nvZT1Bleh+4I1j86wGw74W132\n" +
            "A5iGpedSFqOV1vFhVKg3bCz9ZkJZVtorAgMBAAGjggEwMIIBLDAfBgNVHSMEGDAW\n" +
            "gBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQUbEk2rS5YiRI2UUE7VFIm\n" +
            "JADTynUwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAP\n" +
            "BgNVHRMBAf8EBTADAQH/MIGvBgNVHR4BAf8EgaQwgaGhgZ4wTaRLMEkxCzAJBgNV\n" +
            "BAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRkwFwYDVQQL\n" +
            "ExBleGNsdWRlZFN1YnRyZWUxME2kSzBJMQswCQYDVQQGEwJVUzEfMB0GA1UEChMW\n" +
            "VGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEZMBcGA1UECxMQZXhjbHVkZWRTdWJ0cmVl\n" +
            "MjANBgkqhkiG9w0BAQsFAAOCAQEAbbKErwqLymnsshF9fWoJ7Q34GSpXkfvnqLsM\n" +
            "pak8iy/VCfntv9pPMFhpvAT6F4wuoGN4wXhyQed2ZuSNZlu18fSIiU9aymr0eyJR\n" +
            "XuNHHGjVe+5NDfNkHWVX6sQoH+fLUTQy7SmXK5zFrXynE4GJRTzq3oFTTdnI8HGS\n" +
            "f3YE3wpv0miYrKV/YUz/Sn3v/FV9jqhUU+uMqeOE6o03FX+6wXuZ4FWD6vhbLBpg\n" +
            "2GG3bjZ+ZQAShn10yvZmkWFyvwGinzcqKwI2aotX4eKGTfE1Mx8eFoRVO/1Iiu53\n" +
            "HvrXVQtKgyQkEqYm8py+fJbg7PZ2z+2bn4b+5F0TPI2sJJ2ihw==\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsDN5CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEXzCCA0egAwIBAgIBQjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTzELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHzAdBgNVBAMT\n" +
            "Fm5hbWVDb25zdHJhaW50cyBETjUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
            "ggEKAoIBAQDuAvtcHk5Gye8SvdckoKSvZLwTjNb95iDOOSpUaijVx5NcCubuosIX\n" +
            "n6Hcxc4FI+z3vjoMQr0SdSiATv2QUFvYDkvAXKuZGrWE80oB693w6ljI1iVsT9BK\n" +
            "O8VBdSRFtUaH5fZWUds8Ed6G8TEcybyp/Fi301rGBtcS3Ci4s2eooruWt1EbZUjx\n" +
            "XhxebXGD6xeGgifVtVvZTUySNJNMLxlBAKw4zYX4ZbB0SO0sSMB1fq/OaDvRvBZu\n" +
            "mxJOBCzC7TUl4rhfi8PWaC9gdrsAgIl3pMt0A9nLVE76HL1L5kJnoZDfwFav+/ix\n" +
            "3Rc/PIQ7hqTe+LK4MJ/QW0lZRYesXHrdAgMBAAGjggFOMIIBSjAfBgNVHSMEGDAW\n" +
            "gBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQUup8JypA5nE53Wuv7EJWs\n" +
            "06dKXScwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAP\n" +
            "BgNVHRMBAf8EBTADAQH/MIHNBgNVHR4BAf8EgcIwgb+gUDBOpEwwSjELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExGjAYBgNVBAsT\n" +
            "EXBlcm1pdHRlZFN1YnRyZWUxoWswaaRnMGUxCzAJBgNVBAYTAlVTMR8wHQYDVQQK\n" +
            "ExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJtaXR0ZWRTdWJ0\n" +
            "cmVlMTEZMBcGA1UECxMQZXhjbHVkZWRTdWJ0cmVlMTANBgkqhkiG9w0BAQsFAAOC\n" +
            "AQEAAPGe7Q+EIK4mWtMfDbJlcdLNvAPB8lvaDyM5Tb8cnsDALQfDywVfxhFgNcP9\n" +
            "yPE/NPEo6icOToJKE5wv6/jA3eEs1CPK1HdadnKLMzp2xwcUo6ztMHiPeyGe0amO\n" +
            "HbqUj5dfo8CeNkFsbOcSaCgN9FQl8cQ8/nld3pvX+/tacajBrKWBvLocVTnVSGWx\n" +
            "1TGsB9JkuQtm2Tvr45+7FwzViuu8roIBtFpNMoWLSDU+SG5BB+BaKPT1bA+N79sk\n" +
            "EPGld961zpkq4+53ZsUaaC+WVoXSRaafXitou4cFojEglrhqW5MkmaPDpmBVZ+ke\n" +
            "w786OZvGQ3aNK/RAKRQ7fl4y6w==\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsDN1subCA2Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEFzCCAv+gAwIBAgIBBjANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
            "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
            "MG8xCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
            "MRowGAYDVQQLExFwZXJtaXR0ZWRTdWJ0cmVlMTEjMCEGA1UEAxMabmFtZUNvbnN0\n" +
            "cmFpbnRzIEROMSBzdWJDQTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
            "AQDYfm94+1UckIWrnwOecmHcjFD/KNLTJI62cn3LBu7L+B1RsbKRqB/a8NDKnSjd\n" +
            "8LaqxYztPgbS9ll+67sq/Y9DTSGTep0wFJwJS2n+wBTu88BhOMwMX6JjyCFSM9a6\n" +
            "1nzfk7X+mRGpcSyeqVABl173PxPFfyV2HSagyqLtwc/8uouKrdhcTFgTzsyqOBzp\n" +
            "f4+OTB7XuXt8hYdgCfNlPbX2g8kH2Db4Lx7OcrJgP9Ybb2pQZQ7TiBRiK0EJa/WH\n" +
            "hA96xmvR9Sq7lXnsk09f3lnP3KPeoPfd1wN2rRJ3aMl63dAbfBEdzX7T7Z3RJz6N\n" +
            "bdndTYyo4SKwmO8kknp28pfFAgMBAAGjgd0wgdowHwYDVR0jBBgwFoAUQXhCRs1O\n" +
            "qILn4Tnf96kWwAr874YwHQYDVR0OBBYEFKIvWINbTJWXt+72h7SXDuB/4JcVMA4G\n" +
            "A1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYDVR0TAQH/\n" +
            "BAUwAwEB/zBeBgNVHR4BAf8EVDBSoFAwTqRMMEoxCzAJBgNVBAYTAlVTMR8wHQYD\n" +
            "VQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJtaXR0ZWRT\n" +
            "dWJ0cmVlMjANBgkqhkiG9w0BAQsFAAOCAQEAwEwa9JZVYlDzDjZFQxuAlxD/pw1x\n" +
            "by1ylmOBJnq4eUoS2fwEm75O7lQKQmgvLnWtvy3vnrocTKFTv4jSYldVGqT/Un5N\n" +
            "aopCuIiH44Lr7z/daBQuSPsWPvtRK04DrNXG7BRj6bubn+DdjTsNT+V7HaFwBm9O\n" +
            "8QFm7V2T7NmeElnxcasfNrk96eHgqMyOt/nEuvklmA5pJbcmqOootaIkaPfLlvlC\n" +
            "eE4BlzmDApxSsQzHGHX7W3l8Ulow9BjylZtRRPZ2uM91kGattzhMF6t2dZr+ey2C\n" +
            "BHze/rS2PoFqCFYyRyTWchqXnifv5dqV775zO8AadT36bE3vsRzKogXLfQ==\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsDN3subCA1Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID+jCCAuKgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
            "bnN0cmFpbnRzIEROMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
            "MFMxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
            "MSMwIQYDVQQDExpuYW1lQ29uc3RyYWludHMgRE4zIHN1YkNBMTCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAPnsQIGHFaqj7j4q4DsZNAUSd/1bjxVoJE+G\n" +
            "wqa4MeAzBStBHuQAiUJ5PzxiTWtiUklQWrTqssx5qEAjUh3xE/muB4b3N/+v/A++\n" +
            "oeolkUcbaCGqRUr8pQA6aYQNZJr3XON/6VOrLVwkKiOMAO6Ur8BZ2S08I2r+38aG\n" +
            "b23AUyGQB3sFkn4TmC5eMSsY6SXBvr9bqsXJiT2DuORbB9sk8Cy07nOI37rO13el\n" +
            "/51naQOf6/3S7HYYBemL6pIVynu8fdhmzZ9l6CHy787KDMOs+QJINoa1qW754QwB\n" +
            "wLIINtubz1wMrgs/DWpx4BwSidD+L1bGOmTaFrT63lHb25NswAsCAwEAAaOB3DCB\n" +
            "2TAfBgNVHSMEGDAWgBQG3Fu+xxI3WaSKQHR8CZ1FPEqh2zAdBgNVHQ4EFgQUgLzH\n" +
            "LveOGn/xOHv0Nevd6VjGPFAwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYK\n" +
            "YIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MF0GA1UdHgEB/wRTMFGhTzBNpEsw\n" +
            "STELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEx\n" +
            "GTAXBgNVBAsTEGV4Y2x1ZGVkU3VidHJlZTIwDQYJKoZIhvcNAQELBQADggEBAHCI\n" +
            "IAnj/BU0M/5JGSoDrSkxi44+RGnAKP/18kgU9hGMgm7GBqJ8rb1azbS8l6u6GW3d\n" +
            "qPyisyXvr2ZBL3L08mgkHEJgRh81KQ4pGID6RGghB/DYWfpyxetMuGjQnkD4eHJQ\n" +
            "RriILKNU1JIUEdF/uQSucYCnR9tF2SKvRhSMvQipNKTpHfQ+utig7wIYvFkmc9Rn\n" +
            "4kyoAxjoj6IwdqiFBtMoePG5R9xk3nQZsjTP5WFS+OyNc/xYLMXh/eQ15C+BC4og\n" +
            "1FGFlcLSCI7tvgKYXk/kpWwv4F2pxsvjBLgZq6IsNbCTBNxxNp+QOID61Xkb1U73\n" +
            "cjSJjvAqxW/yqlz97bY=\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsDN3subCA2Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3zCCAsegAwIBAgIBBDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
            "bnN0cmFpbnRzIEROMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
            "MFMxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
            "MSMwIQYDVQQDExpuYW1lQ29uc3RyYWludHMgRE4zIHN1YkNBMjCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAMTpZN/9lfu5qnSxBzxNYREzs0oW+EkQC6dV\n" +
            "6lTASGBtvdK2rJyFeuhlKeGsmRrF/f/oLbGHodn8POv/vhGA5MFUty6gyOQ86oEh\n" +
            "p/J5XbjMtVd/MGk+oc+d0gvrvN/SdqLpSE1u0hTkavMfEd44PlnNVmnT5ksN1Lcz\n" +
            "yA8QLBuG6hsxEQygs5m8lFLgftMdFRUI0/OKOVp0MVwCB+LqWqUKRsv3jgH5DAcP\n" +
            "ZyQ5Auf6gkH74uxQKDsSTIuz0PRmeNDTaNExT7DXysaafv3Xat8/dvARlcqlICdb\n" +
            "UrCgJ8ccpEqlcdelfwEqts7i1oWDOj2F2qct28YSpmi+4eWmacMCAwEAAaOBwTCB\n" +
            "vjAfBgNVHSMEGDAWgBQG3Fu+xxI3WaSKQHR8CZ1FPEqh2zAdBgNVHQ4EFgQUzATt\n" +
            "aigdft5k6gCIKux1Eb+lLmcwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYK\n" +
            "YIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MEIGA1UdHgEB/wQ4MDagNDAypDAw\n" +
            "LjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTEw\n" +
            "DQYJKoZIhvcNAQELBQADggEBAJLF4j1s6nKBt1jK6gDyUmQurPyPtSxoGKv4Ji2G\n" +
            "ChM5qgFvkqj14oEhcGA0I3mjl0uCmGbUkMtrzDbTwmTAzs1CE0NmpMkAbsde/6Vk\n" +
            "L5biHGP0HlnZwJ+79ol5ljpCLKnRETUnrh/t6Wwmkxar4K5bfDFG55jF8WFEG05y\n" +
            "k1B69jPLilyHaepHYd1rw+eqE9x1me2ESMJ40bv2mX5Yx0QgSaeKsr1RbuqiNwhs\n" +
            "LQ0HrQkQ9TsUfVL4g4KmAd+HaSV3lupWX8v9lhUJkajtVwf/cjRmQCOCb8vUHhoH\n" +
            "6KvWIoq7MiyydVHykCp4rL8NRhwCFoHGdGIMdRQhvXlMtR4=\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsRFC822CA1Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDujCCAqKgAwIBAgIBQzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUzELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIzAhBgNVBAMT\n" +
            "Gm5hbWVDb25zdHJhaW50cyBSRkM4MjIgQ0ExMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
            "AQ8AMIIBCgKCAQEAq9vbr9mMpG3/bg2XQGmxlZSEqeJpOnQUuEoS4cicFxpCaKMK\n" +
            "OrGLlpwTrGhR/NGHOEzUO7qLWyTaA2wthe0ohZIsxjvGKK3yMvmnFNriMBt+md8i\n" +
            "PAR0ysFhBmMyIpwdJs1N2jBnOANPW0KFOtrFgncHnEOajo8l0jpGBaLA3ryhdwB6\n" +
            "h/L/A8bNbqJL4E3foEk2AsOzdt1LoRUaA9gcXCo9EqQ29a+598f7NvRME09teL9n\n" +
            "iJEzHy9Dwxy//II6FnlmjnvGdUmm/2Z71UbzkpiqjD0w0/jBXcDAlwTF9EfL71rF\n" +
            "wDCRfZppGRUKLqMNTohHKYI4ilkD/oP75a1EKwIDAQABo4GmMIGjMB8GA1UdIwQY\n" +
            "MBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBTIao6xD0uqpYi4p4+R\n" +
            "2+ozSujV4jAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATAB\n" +
            "MA8GA1UdEwEB/wQFMAMBAf8wJwYDVR0eAQH/BB0wG6AZMBeBFS50ZXN0Y2VydGlm\n" +
            "aWNhdGVzLmdvdjANBgkqhkiG9w0BAQsFAAOCAQEAcAR6YeKZpZPVB0ICn2GTD2Q1\n" +
            "FlSS7paAINYzC59z6h8ynJFGp40/67SrFz7IBzBp5E2InzQ35dBXINNsxcG+xzgE\n" +
            "2PmPZXzInzI5MCJS4XpX6bY94yUTslpoAiVJxwISZ4Gbfd9M73evvcxymSVNAPEO\n" +
            "AX/6eO2ilazokSR9D3zQVOe5lxPshorlX/WlF9LvCOrS0UcEhHoDrfAM6KhojUN9\n" +
            "K5l6Fv1NXwb/8cAbFyC2BMmwmec6OL2oBDJCxoLrAWVaPh7+YZadnLw/w930IIdT\n" +
            "U4C90QPUgdFJWZv13TePZ2WEMtxsev82AU4PjeUS+l7c2FLW0zavMoaPhjPnaQ==\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsRFC822CA2Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDuTCCAqGgAwIBAgIBRDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUzELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIzAhBgNVBAMT\n" +
            "Gm5hbWVDb25zdHJhaW50cyBSRkM4MjIgQ0EyMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
            "AQ8AMIIBCgKCAQEA5WbcU+FNFY3n/eJc1k45UKjs2clgZI0HMujImijlExY8DG9c\n" +
            "FZQuOX7g1eCaHXFeS7HSVMrfKLO9tOSUfYUCido4TA7xhl7Y5l5BrKkn1ZgEgGFf\n" +
            "Z6lZqqb5C6+qd3cUzNPbOXd1HzZJNcV47uZ1NusoqMyXKEpRQUW3t+V6dp3E8JFz\n" +
            "VCLmRPXtqY5JpZemmJD5VWe5tj89OnPk6S/HLKUeNcYiA7rcpZR83TJHmO6tjF47\n" +
            "Bb/hgxLNRYToTn+Z69e9VJ3WZM/t9fJxRUWwEgyBGW48kQjYmGvBNzrlMdCq1ncy\n" +
            "Z6JoBk7UY6qky21uhaO5sknZajTFPTj+M4YNeQIDAQABo4GlMIGiMB8GA1UdIwQY\n" +
            "MBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBRRgM36SXJIPO0OTgvO\n" +
            "zh9AZRJwoDAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATAB\n" +
            "MA8GA1UdEwEB/wQFMAMBAf8wJgYDVR0eAQH/BBwwGqAYMBaBFHRlc3RjZXJ0aWZp\n" +
            "Y2F0ZXMuZ292MA0GCSqGSIb3DQEBCwUAA4IBAQAk9GOd+egKHy41DnTObsmqsc3w\n" +
            "KSvj1SVn17Hda1gq3tLXUcNqp0g7kP/YNXRx8XXxU9heUCOTR7JLVO5AMVS32Qid\n" +
            "J5u3q2D7dBgHN5Nyv7YsUOI+AcVysLMTlUu6iGnwCSsdtL5aJtSq8gAKZE+HJZwl\n" +
            "iR73kSPGr4J1MKBiZvcVa6L5LKg88FQiSdOPJwyPurvn4t/K27u9jW0/SYg1qeM2\n" +
            "/iKSyzsf9bM97aYqqE3P7DPHRZeXTZKLCaMNKAmZ2iWtsyc3aNTn2RyXg6RBUoY3\n" +
            "d8um+8xE71cKdDjNwdJrsPwFhbripzJ+eE7bWV8v5e5E1dN3AzJU31wG1+vn\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsRFC822CA3Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDuTCCAqGgAwIBAgIBRTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUzELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIzAhBgNVBAMT\n" +
            "Gm5hbWVDb25zdHJhaW50cyBSRkM4MjIgQ0EzMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
            "AQ8AMIIBCgKCAQEArHS+/nwL4IEPwwXe4efteEWKpq1uL3iDHm61D3Jb/GQKFWoJ\n" +
            "lNz1VElMoVCqYG++hdGHbQB7teD/59MXxojFdcisSIAA3pTBBDj8c0GFzucAzagw\n" +
            "1IPN3NDjoHJcY1eRg+bKpwrROXxWHsIPnkULSJ++BkMarinmfuN1TjdtKT+Bv6yH\n" +
            "vaCgPxck63Uz+lVHuVyA5feLp6NEn9ocaATeo9JanbiZEPLm3NVYMqt2yzSMy2UR\n" +
            "MJ4dyD14P2L8dTgjaDD22BwpjiLc7gSCrLgTOut25JtYIqreqMn0HWQTbkg3MAg0\n" +
            "S6UTRnFVUR1vfHRleGrqMU1BU4VQRFan8T7HHQIDAQABo4GlMIGiMB8GA1UdIwQY\n" +
            "MBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBSaujlN2iF1r+pBwzxs\n" +
            "UdioRal/ozAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATAB\n" +
            "MA8GA1UdEwEB/wQFMAMBAf8wJgYDVR0eAQH/BBwwGqEYMBaBFHRlc3RjZXJ0aWZp\n" +
            "Y2F0ZXMuZ292MA0GCSqGSIb3DQEBCwUAA4IBAQBhd8WP6gnAMqbdGdka9QLQ9t2x\n" +
            "Xx9zp6vdHGl4oJVmDw2opfpAXwhRc3mQ2MsY7KDfmCNvw3ry6EFEndGdinzfWNE3\n" +
            "4arjKO+uVFiZCD5O4smVklvpI4xFUZOOxClcJFa/tqicdLNF6tA+reP46djPfuUB\n" +
            "W9c2XDBNipVjX4w3f1i4LKTH+imhmF0L3hoHfvwyM26RW/j503HvUHPmX6MeSBjP\n" +
            "HqPfDUgwxtaKbcG/FC7IgCnaKQmcawjIgkWVVz77aue9UW01mJum1dW+7vuZ1gE7\n" +
            "S3waoAlURTU97IgWymX6FtYnHrX/MiQhexsapFHxXxs06l/up/7k/2m89vKX\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsDN1subCA3Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3zCCAsegAwIBAgIBCjANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
            "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
            "MG8xCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
            "MRowGAYDVQQLExFwZXJtaXR0ZWRTdWJ0cmVlMTEjMCEGA1UEAxMabmFtZUNvbnN0\n" +
            "cmFpbnRzIEROMSBzdWJDQTMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
            "AQDELVS/5i1Vg6yF6gHTSfiiT9ULjd1sFFXz2fXI53H0P6d4KAs6CS1swI52BA/X\n" +
            "H2sg3RRnFq6bkwYtkGdUBBLEoIjduP2ntNzeUH5Z+Wma9XiGXSmpG4W9rkpxYB80\n" +
            "6B0H6sJ0wkSqWjcCLxsAO0E3xDlkSZIxLkSTeXv0KuHwKC/iqQk1yrjIrw05qhWQ\n" +
            "JcCQRWHyovQsIomY3TXKrCzZGdlVzX0wBiu/p4uzgo41Fg5OCElt0ic6D7Ds8dsN\n" +
            "DHANWBy8Soo6OMdgtH37U35HS7r/YQRKuxqRrmrv5yRuVnEYHz2oBA2Qdzemb8or\n" +
            "KeV89jjvkZOqhw4RYQBDlKyXAgMBAAGjgaUwgaIwHwYDVR0jBBgwFoAUQXhCRs1O\n" +
            "qILn4Tnf96kWwAr874YwHQYDVR0OBBYEFCdJ5ATZRfpsmJRs/O0NwyRSbVVEMA4G\n" +
            "A1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYDVR0TAQH/\n" +
            "BAUwAwEB/zAmBgNVHR4BAf8EHDAaoBgwFoEUdGVzdGNlcnRpZmljYXRlcy5nb3Yw\n" +
            "DQYJKoZIhvcNAQELBQADggEBABeREf5wmcEhE5n7e3p8axLkSf8m+dzgp4ibNJz3\n" +
            "L/AHhHQOSWVpz6w/4qerFs+ZpQPkt6SdPYmsyGSQaw3hEYZ4mKP1wYIRoBNN9iy2\n" +
            "TaZsjZKMPdqoDUoQnBBXdYOOaLgOFfYaCD2AJRGbZlOqTwPZHHFrATZJrOfaXfqf\n" +
            "Op+6XMfwflnRs9wt+2E6URRam/o9/i95MCysxE8FIUcFAzxr81UzOyWXysKCN2aw\n" +
            "QxbWkWOlrjnA4+oTghMtR3ajzL8F9ryk5PYwDxpXinoGuTNbAfA/y2At09Y8v773\n" +
            "CwAw83sKoZfejzc0m/+7+fNhJuaG4J4C02v2XlafWYAvY3k=\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsDNS1CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDtjCCAp6gAwIBAgIBRjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIDAeBgNVBAMT\n" +
            "F25hbWVDb25zdHJhaW50cyBETlMxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEAxyZIOtzAZ9n+6Fp6UAqnUpZYqyvCKSvTt0W1Ww2idbDJFczQcqX9\n" +
            "lQDy/v+NoGkpQbjqZdrATmomnujiL4AQVpl01V1XJPLySeVOqToqhbzifoy+RBYq\n" +
            "sXewuEDBpy2FGMaFz3JIK8mbK/qQOBFOG8fzzv9gNIH02AQpdC+J6Df3TB0utyiK\n" +
            "PjHHGFWifSswFqCHGG7geXeE+Ep+iqIm4MKKtRIG5DeHiqugcHii+HpaXFASVkIr\n" +
            "Eo1FmWLDE6Ww8m62Si8WQSkPfkcEMGn8s9MXI8L0DT5OlkIVvSs6Fdd24gJJlPC4\n" +
            "lrF5g4P6/UPHFvyphDptCkqpbkBKQEBXUQIDAQABo4GlMIGiMB8GA1UdIwQYMBaA\n" +
            "FOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBSxqhfw48/M0qeJpoMH3f9u\n" +
            "2gfjSTAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wJgYDVR0eAQH/BBwwGqAYMBaCFHRlc3RjZXJ0aWZpY2F0\n" +
            "ZXMuZ292MA0GCSqGSIb3DQEBCwUAA4IBAQA2cwKSvsy7ORVz5Al8eYcC1Y81FdYA\n" +
            "ioDGnr+x+6/I+pskqBFox+5QHN/ccd/xOeFjK1tQCq7WTaEiFWme4DmatuFAMtcD\n" +
            "LG3Xng+yfEeXswsT2L+e79o/Cg1G1D86V+YArRRTGBvIpzNu0owpW8AhJ3us9P31\n" +
            "e6ZRcL3kwuyx/nKODVoTupVE+YJwzLqtMKtF7EOfp9zQK+jSfTUbrmq0y2gqfv5V\n" +
            "5wVjI3Wj/7N1T5cKfPTnRyAoSZRSmZTVVRZgz7wEZSalMLlrCKv9UrTP00WX2n/J\n" +
            "33mL/1KX/Tf0EwaOMfjWj2otCksNZTU5QoMmtVxBhYd01nTV/bKejbUE\n" +
            "-----END CERTIFICATE-----\n"

    val nameConstraintsDNS2CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDuTCCAqGgAwIBAgIBRzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIDAeBgNVBAMT\n" +
            "F25hbWVDb25zdHJhaW50cyBETlMyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEAvfi8NX1OP0jd2b3bSoIyMixV6E+/kY/Uax1VRBts6UW2lx2CYk5e\n" +
            "aF9/9jR3lx24bit3RHNHk7LcaX5Wkr1YE5ROpyxEwhEOGWnK7GcM1MlFvpO9Bj6n\n" +
            "39wr3aB9MOHSOS1ihfY99mY7UINyWNoXzkUD//ivf3Guwuf7lVfvjXwotgcs1ig5\n" +
            "2wSTK0sFONYdCtZMcrslFgBOhm9qZ8fGlOSVAoxKq5Fhpx0omn3DYInXNjHPHwJc\n" +
            "wj7D+8FBY71FHDG7oaeyhaU/kYiQTMAxoUd7XDibLf7KUQ38EiVpLshCNNFTZb9A\n" +
            "56l+03RieJzxNd3OmIULd6AFLNZ1aMOjVQIDAQABo4GoMIGlMB8GA1UdIwQYMBaA\n" +
            "FOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBRGSJxCCY5dU3DYFh7gwckY\n" +
            "FTUKBjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wKQYDVR0eAQH/BB8wHaEbMBmCF2ludmFsaWRjZXJ0aWZp\n" +
            "Y2F0ZXMuZ292MA0GCSqGSIb3DQEBCwUAA4IBAQCGjj236wEfbWpLjM5irGBHsc0w\n" +
            "RdmtOLh4Wht2TlaaJOErYwY4HWankOeTjQdJh2fxlOwWewcjplngI24XuY1i52GC\n" +
            "HL3H3CbiXJJKiyNZQyTfUtWaaP9Avp9psb4J9WcqfKBMMl+j3M3Fw2vLFXSRvC7u\n" +
            "bXnaLNAnsMdJoLYdqcuqfG36aGOlouxf5+ATj8nS/EoOjIDS1LjPCCLVMSSURNYP\n" +
            "2royVDt7AH2TzxOT5c0+5nvrx5bs2GOO/77oiLXqu0FJfXsJSOSOrFZ0EvwTOPg6\n" +
            "5jH4zO0aOlP/p1bkpYpVyHh3syyeKTxqdn+TTZl/SoiSLpk5CxK+eFBlQ7ad\n" +
            "-----END CERTIFICATE-----"

    val nameConstraintsURI1CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDtzCCAp+gAwIBAgIBSDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIDAeBgNVBAMT\n" +
            "F25hbWVDb25zdHJhaW50cyBVUkkxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEAp+cs3as6ObnbAg5IEkmXsD/XLGICGl6qVcEKB6eMA0ILAsGdMHRq\n" +
            "ybgY25GUQ+o6RfvTHdD40N6Cqjk5vu9+7aAVjrJ0pdUyqHmK6u6TVcRt+xjonlEp\n" +
            "o8bpkqqgV4i7m51qfLP6+KEh2SKUDBwOZ8/jlYIZeKzVXqk2GZx8+VmWWncDz/D7\n" +
            "v262km2IiYoZM+1VAUixGhoi6ImPeDBE1u7qoxvvBEDKJJ4sj/5+i4yAgr+JNIUL\n" +
            "vr8DaT17SkwRZquWT18yu2qP2KycneKysWm30A6AmAALhFBNX1ljDeLT5U1wBCST\n" +
            "DRP5U4zH+XvAUUEeMyDYMc92a0hjYwE4swIDAQABo4GmMIGjMB8GA1UdIwQYMBaA\n" +
            "FOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBT6KK1BFt4qaBfIDxwjPyYD\n" +
            "3gIUAjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wJwYDVR0eAQH/BB0wG6AZMBeGFS50ZXN0Y2VydGlmaWNh\n" +
            "dGVzLmdvdjANBgkqhkiG9w0BAQsFAAOCAQEAW+m6tH95z9aBJUxdo/dsjRTdVgxP\n" +
            "LGVODxeqpW8IvEEjoYBWgHT5M+g4WYnzeSjiPvrq1NerYU0DOI2/hb7aoBBq+7MJ\n" +
            "2q6BK06ddUTawRhLh4Rfnc36epefkZLKtQuFBKA7xaqWLlRQa/jMoZ27hKI5b1qr\n" +
            "aKR+iP1rKPd1epIL4nwqQgAd6z1bJrV8c2V8py7TWE7/b6wuZVR4aKtFMp2fIN0e\n" +
            "o8U1K35YVtmuVw3TJsTlFn/DuZ4R4Tl6GqkdUUvlKXNuY/nMobgfruTG6nvmaLyy\n" +
            "FHtDoamjegjbIx/N1dibXZLf5n32iBXyHHDk7L3ubrarUrutmaHgEEiFZg==\n" +
            "-----END CERTIFICATE-----"

    val nameConstraintsURI2CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDuTCCAqGgAwIBAgIBSTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIDAeBgNVBAMT\n" +
            "F25hbWVDb25zdHJhaW50cyBVUkkyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEAvl+AJxWs1WMO+mjRtv79nQQIKiD4ZerSA3/ELaH8hFiF7zjMQ5iE\n" +
            "LbNmILHWH5vqaHVmiDRbxuoe5fcWO5B0YB1A/dFY88kGTjB/TSgt+CBGdF7Lmy+O\n" +
            "+JwL5EGiIerDfte2+OpsUDXmwvSa5pP69kS88il7WuZcbJZgcAJ2dH7s4c0oQ4RZ\n" +
            "pKZitazyeruYlq8ISw0tMyWUhQyIBtnpaRn4FGRpZhwdn3MzpBsMXEBfETqDaIT/\n" +
            "Js/NHI9p0BldLlXxjTci5DO3JD+5eEwzjmXepIER/xKNuTEgK2ZpULY8JyJxG8Ep\n" +
            "lenySFLq129D/VbDVJjp5PAj1wJKLL6OLwIDAQABo4GoMIGlMB8GA1UdIwQYMBaA\n" +
            "FOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBRN64lx3/AEAbL6djpYsbpg\n" +
            "3YzTwzAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wKQYDVR0eAQH/BB8wHaEbMBmGF2ludmFsaWRjZXJ0aWZp\n" +
            "Y2F0ZXMuZ292MA0GCSqGSIb3DQEBCwUAA4IBAQBmrQhlvkrzTPT4BYr4agHBUoLL\n" +
            "n444+NPFOwy4rQOIOY0k++Fpvn+jjpIzrHMor9afu2rMHJDhlcNia+a03Ov1cLwe\n" +
            "9fmf3gR1V5AuSjTJiLEN7IWADuIVcAPbAgg34e9Qb27pfVOnZ2JmPHkxiVMlGtA4\n" +
            "1AZXwDD70gZU3iaIQKVPmMbLyBZHv8c3XtMkZ0JstPgr1WJ/Vl/Xu2fmQgJOc5tC\n" +
            "z5fPPQteE5Uas/6COzeAL/VRAqfysO9jh7T7xfs62bbqxGcQise6bLxqKnpd5KWW\n" +
            "BX1dDMZrBsEziR4j6wczx0fhfEPH0VPileMDN1o/V9YO9RFo1Y4+0YUi8C6P\n" +
            "-----END CERTIFICATE-----"


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

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid DN nameConstraints Test2" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDuTCCAqGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGDMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEZMBcGA1UECxMQZXhjbHVkZWRTdWJ0cmVlMTE4MDYGA1UEAxMvSW52YWxpZCBE\n" +
                "TiBuYW1lQ29uc3RyYWludHMgRUUgQ2VydGlmaWNhdGUgVGVzdDIwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEhHHtIQeSm0sk2SFRU1s6R4tZgm0tafsm\n" +
                "dRRDgwig7Ne2fUawQFelK+hr+kMzQJMCb+ogMkzZfPtgOjDnhH7Z2964MaZPHzpf\n" +
                "JlxY4aM6A91wZ4WopRp24jyeMmKlH/CO19LqjOc+UBuhtGUHKk4ZFdPac3PMXIXj\n" +
                "x9ogd57ttbYdjIk9Ix+X+o/tPnrL1Lp4RSjhkPs4VnsOkm90rgxEwNZTyCTgNVkc\n" +
                "qhJE/0eXgBIV7ZXc59uS1TDVImybZa8NY79ClvJ0Lhl6mvtPnoUvOgOZh+SQu0nh\n" +
                "OOuy8hzmhqNLqTYkTDzjtVzOHW4wKZ1qfwVjcmXq0fCR7uyHdup7AgMBAAGjazBp\n" +
                "MB8GA1UdIwQYMBaAFEF4QkbNTqiC5+E53/epFsAK/O+GMB0GA1UdDgQWBBT8c/+k\n" +
                "4lqB9ybLskI79g0ctafZ1TAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQBW6ljxbVxaa654QlFBrLWa3bDc\n" +
                "FfC1lnbmE0Ya1pzkcIbsD+ayZ0JcKcuLPUjWp36m7BpuIrmEpndmc1O0cEQyqveH\n" +
                "R9vfSDxd3/R6jVMQbFfa10HVNDmlKrjYyIq+FQla0qv3qn3W2icJWRds031t92+6\n" +
                "gb+fLBd3YMXEtEH7+VCQNyfVZo+9F2xoUTxKWSr52jsxsMaIdRXjZUIZBI8pZI21\n" +
                "QcYSdNPk4TxvHgbQijY8+n9y8qV0aPUckZOjo00KczVPtytT9v5tzvNk3JubXJ9W\n" +
                "hh+9WSe9uJT92xu6e3aAt1WVhCx0XIdg49GK0hFQs50dTT1mLAoi6aGEd8+R\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Invalid DN nameConstraints Test3" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEVTCCAz2gAwIBAgIBAzANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGEMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTExODA2BgNVBAMTL0ludmFsaWQg\n" +
                "RE4gbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRpZmljYXRlIFRlc3QzMIIBIjANBgkq\n" +
                "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxQ+BCdHFQbNq1Bp0GEuyOvaYS2gc2xwp\n" +
                "YD7153M9L0wHxwNCAnjTjFdAc5e2SLlaCI8Bb3ZbGl8yTKyXaJ25CceHxpyzNWW+\n" +
                "elq9FJDZjGpxZ5hbiYnhdkS9RVwgkDbVXwv4QfU2blSlQy1vyAH8gfy4mF5XJqfh\n" +
                "58o+tcECrOZcD+116VHrK4HIMsp+FBGowH6VNhuyOOp3FaXII0NLLUVjBsjGwbkj\n" +
                "3gFoTq5dPnTuFkr5Q3RQw55A9vcJkmzxHbZko1UiywiVIbcXHneqWrKgyJCp00sb\n" +
                "w3gEc1Gk8jpKtluNsj3ogmnRrG27SKjcpVhZi+KLzOkAEOvBAVU2/wIDAQABo4IB\n" +
                "BDCCAQAwHwYDVR0jBBgwFoAUQXhCRs1OqILn4Tnf96kWwAr874YwHQYDVR0OBBYE\n" +
                "FDipyuJ4S5MA+1KCLlTd2a5ByjG0MA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwgZQGA1UdEQSBjDCBiaSBhjCBgzELMAkGA1UEBhMCVVMx\n" +
                "HzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExGTAXBgNVBAsTEGV4Y2x1\n" +
                "ZGVkU3VidHJlZTExODA2BgNVBAMTL0ludmFsaWQgRE4gbmFtZUNvbnN0cmFpbnRz\n" +
                "IEVFIENlcnRpZmljYXRlIFRlc3QzMA0GCSqGSIb3DQEBCwUAA4IBAQAbvjL5yhOt\n" +
                "fWiiB5PSQ+FM3M39S/xDOI5uMQpo0Z/KMs/ENKT5SVqKeOGuNOItovk0pNpBfrOr\n" +
                "8jHuo4KuZbWiVUFSrUeB7gX6lJHXoM+Vqa602UHkrxKeZVQGEQ899RTysUH/zW5e\n" +
                "RIRTbU4GVuYYyFl6PXp5Ve7Fb5grC6moak+bzuF0eN/GTrp1o7l036LHSdAbi2qz\n" +
                "Blg5KbihSptmhELFjnC2lZyD6eyYvpcBeW0qUjH+PqQzqdOnrxpfy2aH0qGWceMa\n" +
                "y7RE3OZklQsUbF06hrhuviBgkz988Ih/fVXtANKOIrdsEZXx2UoHOGILDpZxa+WG\n" +
                "Fov/1Hl0j699\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid DN nameConstraints Test4" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID9DCCAtygAwIBAgIBBDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGCMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTExNjA0BgNVBAMTLVZhbGlkIERO\n" +
                "IG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZpY2F0ZSBUZXN0NDCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAMwAaxtQyCLrv/YYGDvG+VDVKwvJGevkTOK/\n" +
                "nOJK5GsXCbEgAwofTRjPkMXBdn7oSucjXzlMKnmPvaKh+e/fQKaNVlicqKoSOomS\n" +
                "4KpSguNxEIzWUxDuMqfDpOCSZYIVc9PdCcLwbEq8lnYttJrajQrZUTlDCoQoHENv\n" +
                "W21JsXe0+fbC0zVw2MAHBVniFhssPtRso199CD/J7t0iCBI7phy2tjvWC5cfUUNv\n" +
                "DObrRNF7si3GPXHPUpMe/GmcEIdvEcAE4H+rCqEWUxKkWlyVPxIoPPsiRzqG6+7l\n" +
                "AiMFsssbSNQ44qe93TAr7vsm1/ZhZpL0r/LMsZmNGSidHhYSt4cCAwEAAaOBpjCB\n" +
                "ozAfBgNVHSMEGDAWgBRBeEJGzU6ogufhOd/3qRbACvzvhjAdBgNVHQ4EFgQUCNad\n" +
                "qrso0AGdiySHpj2VH7iF03AwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYK\n" +
                "YIZIAWUDAgEwATA4BgNVHREEMTAvgS1ETm5hbWVDb25zdHJhaW50c1Rlc3Q0RUVA\n" +
                "dGVzdGNlcnRpZmljYXRlcy5nb3YwDQYJKoZIhvcNAQELBQADggEBAMLtM5cSPVV5\n" +
                "t6LSDRihYq2CRqQTpOYhfm6UB87/JqjdIdK1ANoDgNdHWw/CdzwcgbDkt8BhUNwU\n" +
                "EWovi3i8MbcLbagA3/5OooQ9rvlItrRvrIYVSJ/VPWSIdV/tCeljFGeh0Azfq4O+\n" +
                "qLQbvjLBJtjCrMUVjVR+sj3eb6TuobLmIXdk7rGziSNKw49nvBQfqtkCkehuesaI\n" +
                "cr8NCCESNhPopoRBHWRMTilfo1WOeT9U7RAEdolH4fycsnXuq3cXTHpeu9xL0Eqf\n" +
                "YCgGXJ2Y9KUktGRTzi6WJZrMkzvxsdSkVeuQ0nvJ4czWwNn12VbN//OWgek6lkhg\n" +
                "QUvZYUxTdrM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid DN nameConstraints Test5" {
        val nameConstraintsDN2CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEQzCCAyugAwIBAgIBPzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHzAdBgNVBAMT\n" +
                "Fm5hbWVDb25zdHJhaW50cyBETjIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
                "ggEKAoIBAQC+uNFCmZxvCnJAo+o7l2d8518z7l5vjF/XBRG+Tdve0kCfVGy5A60A\n" +
                "SlhV9UvADeYGeYaUdz3Rz9XFRYWClMFY320x0AFalq4154wBCqF4TkQnYBjyNqa0\n" +
                "vLgVgSDidP2GaO8m/sNLn1fGgEjXJ4Dia+MzTgYPJJrD9nuAbEJdrfaQhGutvPAi\n" +
                "MY8kOGUxQuVipV2OoY0N1mcdrJSHDD6nLeDF+U7Sac+dGFv5ip6Di8n5cLliSXjF\n" +
                "cBlLx9LepOF0qYI7iUsHyjql/Zk1SQ6tQziobs/So3sXQOAI4tOfQFfNCoo3XVjh\n" +
                "GU8ya1aLaJ2m1nWIw2bLXcMigGGF4EUxAgMBAAGjggEyMIIBLjAfBgNVHSMEGDAW\n" +
                "gBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQUo1fZW10Rs2D2AGuJUSuC\n" +
                "wwlzqHswDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAP\n" +
                "BgNVHRMBAf8EBTADAQH/MIGxBgNVHR4BAf8EgaYwgaOggaAwTqRMMEoxCzAJBgNV\n" +
                "BAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQL\n" +
                "ExFwZXJtaXR0ZWRTdWJ0cmVlMTBOpEwwSjELMAkGA1UEBhMCVVMxHzAdBgNVBAoT\n" +
                "FlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExGjAYBgNVBAsTEXBlcm1pdHRlZFN1YnRy\n" +
                "ZWUyMA0GCSqGSIb3DQEBCwUAA4IBAQCXLrE60g7rdRWgaKYMWCgs6s0i25R+9SIl\n" +
                "U4UNeepOEONu8pSbj6uUrtGdqPNTZ7HIXzYQ1mPAvz2gGM/KIfumIcZn+A6ZEwEi\n" +
                "9UdHPF29GwEv4hU3BZ/QTxORGe5JxgJY5be7PCVyIr5vMf7RQFKX0W72Se+SK2MI\n" +
                "vPosq6Iufv9L0rdURTq5QKfPXwq8WbnDlDzwar0puc4yYrqsmxvBfDN+9Z/z7gM2\n" +
                "5uoL6hd0D1U/Vo07NNky2i7giYKrUkOBEW/kVXWIgM86ydsQAOsyiIepJTW3b1Hm\n" +
                "gxUGkn20eEftf/QXo6gFD/o0l5dRXSu72Kh8UdkcJO4alD93qB04\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEUTCCAzmgAwIBAgIBATANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMiBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGCMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTExNjA0BgNVBAMTLVZhbGlkIERO\n" +
                "IG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZpY2F0ZSBUZXN0NTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAOd9JgS6UfldtaDuyQBCIZeoLkR28/31qIXr\n" +
                "Idzjq7FP/alv4nz8AofmEYROX26zxgu2e69X0RSGWNKW2bOTuA6V4jgNBKKg3Znz\n" +
                "DjAViJ/V6NgEr6xl/uCW+71awSuiI11C6WJJ9ggxYevrUPHyt4OTM927cvjfnQhV\n" +
                "raL+iKpz2t9/UUyV7xtK8T2rEThTqEeqDeKafwD3gnprACqJpndUR/OgNoUMjdzL\n" +
                "dD+I2AImKlb510UTH9le4E4budK5qjDX5bX1d9txnXKsOClrQ6h5N6MNMUuMEQBQ\n" +
                "soetsXWs+xg2EyRSQbsvfiGqdEdrsrKbvQcNSg2R5QUklQp69C0CAwEAAaOCAQIw\n" +
                "gf8wHwYDVR0jBBgwFoAUo1fZW10Rs2D2AGuJUSuCwwlzqHswHQYDVR0OBBYEFMnZ\n" +
                "gJavUispfiyQDQtHWo0RKMMEMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwG\n" +
                "CmCGSAFlAwIBMAEwgZMGA1UdEQSBizCBiKSBhTCBgjELMAkGA1UEBhMCVVMxHzAd\n" +
                "BgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExGjAYBgNVBAsTEXBlcm1pdHRl\n" +
                "ZFN1YnRyZWUyMTYwNAYDVQQDEy1WYWxpZCBETiBuYW1lQ29uc3RyYWludHMgRUUg\n" +
                "Q2VydGlmaWNhdGUgVGVzdDUwDQYJKoZIhvcNAQELBQADggEBAH6QvBXFcVa5nqff\n" +
                "tPENGZ85VSShfRVZrlseVsXlJEgRR7NEQIiXOQrjj729QVKuvp6ClImPTblzIr3B\n" +
                "uNEylzfqp90bUCDReuVmQo8MXIviG8IuZFRkMYkrSH5XbUgk+MGyMjdp3Wi4WCdL\n" +
                "79plNgv6YErDmbDxy2MBf0iHgFRMzcYy/irtmzOhfa4wCim0Ju9sQaPjk8a995QF\n" +
                "sBhnijwIFrjkJDPiI+JV5EyTPRoE62rshD382LcPmAUvRp4QEbNBHEIh9XmREHeL\n" +
                "AzWS1mu1Ge37FaR1VKmB6aB2RCpN4cmrDf3DF/Kdd5HZuDv5WdowZwqO9Q5r7juv\n" +
                "MFes7mw=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid DN nameConstraints Test6" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDuDCCAqCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGCMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTExNjA0BgNVBAMTLVZhbGlkIERO\n" +
                "IG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZpY2F0ZSBUZXN0NjCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAM/4iyH3zhj0pIS2GVWhozQpxO7h0Rc0VYwm\n" +
                "qBRe3BCR0+gLN6FyWhGksoCInhWVgjCp83tO/AV0egq6mtvYVy4/YnzNvPFuU4Ij\n" +
                "E913+ZktncyEfaJYkjJ8fms83OH/Pah7DpSNVRlxQkvuq8losTpL9l5V7YqLFF+d\n" +
                "JwHKyXmPFJpujAHtnoqCe3f/WwjyAXeI0M0/2b53eAzqJUmiJ6i+qyygNpPp/OAi\n" +
                "vunB8NnmVAcshvzRrCWiXF+XChx80fHQclCf0QblOEW7l4pelieJd6BByYfz7Dnq\n" +
                "Ji3Ep4ULtF5CSVcXyJhtB8tf4XiFAxVh/ifDW3L0SkfuGEwA6VkCAwEAAaNrMGkw\n" +
                "HwYDVR0jBBgwFoAUBtxbvscSN1mkikB0fAmdRTxKodswHQYDVR0OBBYEFJWht0b2\n" +
                "Dg93oRjljC30sI++d9gXMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCG\n" +
                "SAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBADApYud9pWALlHw0vcQGRTQvhNRM\n" +
                "nonPTNJZa2dzI76tcsjPw0BwP08OIKv60ciSIsEQIU/lxUruRSixe7xrxktGygPk\n" +
                "aaOdXnF/WQHhucPx6HKl7cs/c8zInJQKWSG3DYa3rRCtsNSo9A9J3cwY1mAhsh+S\n" +
                "JbZHXu9hbFdFoLPaCHNQRod9aqpiAd0ra7SpzrQGSZMTRaWbQi1mHJ93ay/bBQI/\n" +
                "1PqHZ71szX/EIM9TsHLCV1Q9oJN12xAbDI5VdhuCFdiIDRytGZYu0en48+CDZIGZ\n" +
                "Bi2sSMaG3zmUU7w9fh0NuuL2YlV7C5p96QljGRtmOZh4qoBgOSbrsa3k9zc=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN3CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid DN nameConstraints Test7" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDuTCCAqGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGDMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEZMBcGA1UECxMQZXhjbHVkZWRTdWJ0cmVlMTE4MDYGA1UEAxMvSW52YWxpZCBE\n" +
                "TiBuYW1lQ29uc3RyYWludHMgRUUgQ2VydGlmaWNhdGUgVGVzdDcwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeg0Q4UuYbfP+YbFOzQ9YSaIj6bLj1XqVJ\n" +
                "wNegsJlRNNFOlEqGjLx2s7WKQQz+GhTXN49e09Dnsf8V1uYS02UlaSMM5NKF5mJ/\n" +
                "xq7eOAbq+yzYMjl9GsL8HQghiy9E6igRDOIrvfYDIJydWGMAyMO2AjW0MGJHzvFl\n" +
                "F/kV3c9b9goVmWSvxCzHuv2aTyaPPzXQQpY5ZNkquU12xRiujJzCdiXU7csjySJA\n" +
                "1FHHI3n8oE/+fi/LMnPdBO+rpaLfr/IA5XKUeJUHb3WEXJ3iwi+mMoZrn9doiUvb\n" +
                "gnWUsKmPSoQ85RL0HWVSU/Qw7vItixSHKcKrXCSanL7A4jRWrI9VAgMBAAGjazBp\n" +
                "MB8GA1UdIwQYMBaAFAbcW77HEjdZpIpAdHwJnUU8SqHbMB0GA1UdDgQWBBSFsJW4\n" +
                "SPk0c+uYjBzxBnzjY03dtTAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQAihLqlYMuqWs3P74TsKop+Ilgy\n" +
                "d+zng8ltbEFodH7lYIIdbghsS4nHHmYIApf8Fd++zpf2Vg5NY1Celolriqb8v6nb\n" +
                "VeygO1Mhtwq/yKUCAU2DgSpj3KkbcP4gaS8PwHtSTNzus/soD8jaRd1y3/37QGMl\n" +
                "LxatbtPI3+nHsaVPqwQJfeeyQAnOXGyB2t11LD171aS2uoRkGp+9ZwX1lhXEGV2D\n" +
                "oNnwQ9NzO1JJUWYtnDl0Q9xbWzT2AZ2FXQr4uVBnkdtTOPvpH88gNpRt8y5WIkjd\n" +
                "0pQDFt+EyePgBAKk2HXPImtseHPPH3z+ZRoRUGet4iESVIFVekv5/olJrfeL\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN3CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Invalid DN nameConstraints Test8" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDuTCCAqGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIERONCBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGDMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEZMBcGA1UECxMQZXhjbHVkZWRTdWJ0cmVlMTE4MDYGA1UEAxMvSW52YWxpZCBE\n" +
                "TiBuYW1lQ29uc3RyYWludHMgRUUgQ2VydGlmaWNhdGUgVGVzdDgwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDd8E++Do+azS0Y/46cd+mli2KpLKET6z1f\n" +
                "h6a2XTdv41TEtc0FJwgrEUxzzPX9gbx/NVNU0lHpVs9xoZ3/g8k4sC3/tSB5Ud8o\n" +
                "dNy5yjOzrkCqMmf3dwxQ5bmf/8pQUsN4qch/nCnnLH6LllR8S6ZlO7HD2+jqS7jS\n" +
                "FnGm/ExZs1fvBz647RQi1RxojTdd8ek18y2xMMf5c+0BqNBjuuSQ2l7iWCSPsT9n\n" +
                "UVrvwhJopi5irEti0QP/bUcax7okraeFT0RnJTGrrxIREx+/bvTJ8jc4yFAsmuu5\n" +
                "KsMzROuEPWz6tPjXHJItIAy9hhtIjHOE5tkfFwfBQI6KJpwi0RzXAgMBAAGjazBp\n" +
                "MB8GA1UdIwQYMBaAFGxJNq0uWIkSNlFBO1RSJiQA08p1MB0GA1UdDgQWBBQdy6zN\n" +
                "eXfT6urnrougyDWvP3JkPDAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQAmvLMakt11xX2Nh0adOhzCqqB2\n" +
                "Ea9gZ1LAusrw87JblOzSrHUGrwR3cL/yTAdyNhuudqJQTe4aobU+7DorluFEF29v\n" +
                "hvwtIEHAhw+WRmX/pNZ9txamcYTfH4Pi/HHaSxG0nFNNT4LWTr0ACO61wkIH8FhZ\n" +
                "Y+K6iHx7+e1vvGfuUFimKyH6lW2Ia59LCo3E02OUEv7r/d8z4oc2sH7wYZ1fFlOF\n" +
                "RHzcE/rMmO+3t41Ejwg8WXCrojdeYpWxXjA/kL7dOQoYs4E0fffiousFtMkAi57V\n" +
                "daf/BhKsPsr6vCIucSZVcoFXqVTXhRdKR9bqcczLjG8um0VXD+GcABkC/5Rs\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN4CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Invalid DN nameConstraints Test9" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDuTCCAqGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIERONCBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGDMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEZMBcGA1UECxMQZXhjbHVkZWRTdWJ0cmVlMjE4MDYGA1UEAxMvSW52YWxpZCBE\n" +
                "TiBuYW1lQ29uc3RyYWludHMgRUUgQ2VydGlmaWNhdGUgVGVzdDkwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyBT5iEc/Tv46A838epWd5siS3H6q5kdzw\n" +
                "winlJhMTUca8dVCuiZ9Xwgh+N86g54NvIJXzQiAey/KJan+2DXRcMu5EGOJjABk8\n" +
                "t6jc/oTvdX4KjMkvYobBKcSsRuhuMkCn3vy47e40e8nxhmVhO/f0crEsmWGE4Eaq\n" +
                "pnrcFD3YPRZLaW/2HRWXiOn0TpwJLpus+NYxghAwvI/IKDh5ymBj2BywUvvxngT3\n" +
                "iKQ4BgoT5W/4Ce5XMekn/S78BD/DWiQMHqNjBPeb6eH+WvyPXpn6pTuIGg/Vpn3d\n" +
                "KJzpl9t3WMo0yQaFzYlrUhNYGOJMXWboX27tHetlmdhQ7kF+E8WPAgMBAAGjazBp\n" +
                "MB8GA1UdIwQYMBaAFGxJNq0uWIkSNlFBO1RSJiQA08p1MB0GA1UdDgQWBBRQpDE2\n" +
                "BhuO18HQzangbKt4zr2s7zAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQCom5SmP8qsQSlBzA8HM0nOGzLG\n" +
                "oD7VEV8/kxv8VBLzXzgI7bijCIWzSReTUFCp8gBzdMYLlvXHkfy+5kvC9fIEmzyw\n" +
                "uq7vNwjmFOA2sXtoGcbn5LwOhEepf0qdi2Y5oOxqQRrj98FelZ62bsXjOEKdR5g9\n" +
                "J+2+VcU3P0ENrAQisVy7mw/MteuUEL7v8iEtfpvxjR6ZP9IsRQY2XsPXNX5hzlzZ\n" +
                "C+M3eKDVmg3c4QEjXvbBdhntVU9H+YYaEtQZ2F0vKH/lv2f2/Vj7yupxExakxpQP\n" +
                "6ukRNeDvnG6ujitq8qhWu6QDEfCdzzEx2ZuAVZqTJjAKWC6HwfZUioDjhHFZ\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN4CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Invalid DN nameConstraints Test10" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID1jCCAr6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIERONSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGgMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTExGTAXBgNVBAsTEGV4Y2x1ZGVk\n" +
                "U3VidHJlZTExOTA3BgNVBAMTMEludmFsaWQgRE4gbmFtZUNvbnN0cmFpbnRzIEVF\n" +
                "IENlcnRpZmljYXRlIFRlc3QxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBAMtcOJE/RnaVHILDfZtHlUhM1+XAYb43ZVRpNwV5FSIRq9QuSR5liQ/UspVX\n" +
                "Sf8+7TtcTN2jsJf8mpTsMFRg7bM7U9MYdtKkEMCuSZw23p7ViAdMXA8C1ZTrQP/a\n" +
                "eqWRqjxcnywYAygYhxq3zJ+JPUzKJSOosgfd5bzhnteVXKUktQeOZkoJyi421/1b\n" +
                "eXkMGK6EeMl7wQY0LofwaXVdjo07iv9T5c4CeHhTTctGqxEvpvkx5tf/eP7wEdvV\n" +
                "5sQ9/FxcG+lzlnsi5G1ScvPoHrbWzSL18qnm7cVkTnl5qhKVWrGluFca9UDNgXEZ\n" +
                "fMjrPn0KbHzma61GVkg9+W5SSRkCAwEAAaNrMGkwHwYDVR0jBBgwFoAUup8JypA5\n" +
                "nE53Wuv7EJWs06dKXScwHQYDVR0OBBYEFPh89wp4MlOC1+WYAt+HqvvzZdLQMA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcN\n" +
                "AQELBQADggEBABeqoXPiGjUdCzGWnsb1grkUibPx8tfb31bfSFuo0iWoKA+RVecI\n" +
                "xaepmZjcSRFdYN3lKRiPpmCXsBa8zN3vnQzAc53FGkxKmX/0FCUI/tKAKdeWN4Tj\n" +
                "dahGQAjXBVWBUCaRlonqQ8xDzkWEGIuYS2/indcUZ3b4mp2QOD9tWMbglcRIpwoo\n" +
                "+Jp/VT0GjCncj/NOr5tnsImNUbZDSXUSQEatXsjQCK4kPqRhe56A7AWAXvS28L+2\n" +
                "1BOYIyshE8G/2zYHwexSna4gvhrN23NbvLE0Jib+XzHekc2s2sss26qY7ZlkzMLq\n" +
                "Ad88C6Kz0Va/w3kSxfmhF1fUrmYWgHkJ75w=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN5CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid DN nameConstraints Test11" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID1TCCAr2gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIERONSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGfMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTExGjAYBgNVBAsTEXBlcm1pdHRl\n" +
                "ZFN1YnRyZWUyMTcwNQYDVQQDEy5WYWxpZCBETiBuYW1lQ29uc3RyYWludHMgRUUg\n" +
                "Q2VydGlmaWNhdGUgVGVzdDExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
                "AQEA01aMPpsarfXTbYAgFvrguR7kpQFB2n1BkbdNNhOcH46ur17thybR4gMhgKVy\n" +
                "ILcpweStTS146Ezc4LjdRqKH51Lr/6QMfRF78siZfrAjbG7PDHmyX1XS1nYpdwnD\n" +
                "nkK4Ajzj/CSYEzsASZ0vUt9fjEWGSBjJy2G7GAD4CENSnK9pLStCJiRrOQBNljEp\n" +
                "i4USasjteKMMsmObpi2UN6i3PaypjubH0quqEaTd1T1okLsLhgZSSFQG67toDyln\n" +
                "YggwV9KYiQKlBgNkGESKaQ+5scY0yGmpL41HRdehDEyRDfyhGTld8TiOkDBWI0M4\n" +
                "D0UgdKsEtl266bBheQ72ggr79wIDAQABo2swaTAfBgNVHSMEGDAWgBS6nwnKkDmc\n" +
                "Tnda6/sQlazTp0pdJzAdBgNVHQ4EFgQUEctmOQ3qs8HYJEuov8tpKBE0oKQwDgYD\n" +
                "VR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkqhkiG9w0B\n" +
                "AQsFAAOCAQEAymcKvWtG7XwsLtRjAAyciN0MvZNaF7nyKiPuY6YjdB+N6DDUwGEt\n" +
                "N6yPWHIsTGtQ2QbAGoYivFz0uS6bGAmepNcjay+oGsL5pEGV9hPcCqL51FvFt3eg\n" +
                "w6m0VoEOS6tvmQ9Xd9eKSRtyBgBwVwTdvhbw8qhnh47+F40MThIUa69/Zec1Ihem\n" +
                "LcGAbdvzLOw7vAdu76gNHoECHEtAx0DntWVJqhHHD68NOtFeWCz5/582KYaAhcK3\n" +
                "XVPMI8dkSN9vFkUCYW4A+GfXflQFj3IT+qfhfLhu8Xvw8yfr535h0ollM6dN3OaS\n" +
                "DTwwkN/wHr0evldYdBGOiU44oD0CBxYGUw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN5CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid DN nameConstraints Test12" {
        val nameConstraintsDN1subCA1Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEMzCCAxugAwIBAgIBBTANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MG8xCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
                "MRowGAYDVQQLExFwZXJtaXR0ZWRTdWJ0cmVlMTEjMCEGA1UEAxMabmFtZUNvbnN0\n" +
                "cmFpbnRzIEROMSBzdWJDQTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQCnk6DcIUFQfwdRiYfWRy4EZs8bttqWQv2K4Jtx+hcVARrTeyf3hXCnRZBclltV\n" +
                "x7k2TZQcO6kekgMsxEZJikWB22yP4V+DPt/84pZJa9w+KIcunpXz1ssAfAGav2V8\n" +
                "XgJHzxhd7UPLi3TAhlRR7n6WfeALE3al9cITYH8FPUDYOREbhLGMKpedvZN6sZPd\n" +
                "gPVHztiKu9uOODKJAC/uuaz6/arV+3i/tBTEIDCSUWT55Hru7lbuWURShmLgzwCn\n" +
                "rhnnH/j/5JzPX2/TQtIJFAPVJW6zf2AAPLBf2KgwfHRb6f6FqVDjH2KZUa1Vxt6b\n" +
                "TUq2xWzJ+sZIqqNU67w5RirpAgMBAAGjgfkwgfYwHwYDVR0jBBgwFoAUQXhCRs1O\n" +
                "qILn4Tnf96kWwAr874YwHQYDVR0OBBYEFOE4DhQYFENczudLYscawZL2ZoLqMA4G\n" +
                "A1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYDVR0TAQH/\n" +
                "BAUwAwEB/zB6BgNVHR4BAf8EcDBuoGwwaqRoMGYxCzAJBgNVBAYTAlVTMR8wHQYD\n" +
                "VQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJtaXR0ZWRT\n" +
                "dWJ0cmVlMTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTIwDQYJKoZIhvcNAQEL\n" +
                "BQADggEBABBmPe0Z8HrHPHka4JG5rGDs26rfKj2lIb74k3MJsuytdIUeqbFdCrH7\n" +
                "dEjwAs+UvRgDDRFVWpWpHG32lk4hacMLHTV1zcl6gcdsOubVXfgodDLaZnTMtV93\n" +
                "NV+cGJohowpkmbERLZDtM0/LXJWFbl+BAALPuJ91QwKdEKkImTBY63U1A4BKbmTd\n" +
                "WtHnLgJjYC0Z53N761u7cwfpvxL2IQDKmFNHQI6dMkdTxSv5TOzPrN8A0jr63hg4\n" +
                "D/QBm1Am0fddg+SNx34qbGpGgBorp5pPzowDCQWTJU3qbaJ7wTYmcWIE9uoDmaJq\n" +
                "TaS/SCkPfhwzOPyKNt7KnKIn/acNHOw=\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID2zCCAsOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEaMBgGA1UECxMRcGVybWl0\n" +
                "dGVkU3VidHJlZTExIzAhBgNVBAMTGm5hbWVDb25zdHJhaW50cyBETjEgc3ViQ0Ex\n" +
                "MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowgYUxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJt\n" +
                "aXR0ZWRTdWJ0cmVlMTE5MDcGA1UEAxMwSW52YWxpZCBETiBuYW1lQ29uc3RyYWlu\n" +
                "dHMgRUUgQ2VydGlmaWNhdGUgVGVzdDEyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEAsaY3YvZQ0g7cMEm8Ci7BM6eT6NjOLozJ+1H72HTRBstqGwFfoQow\n" +
                "3jyt9v5Ea1qcrsDbzaCtV2JJDEx5jmt3//MkuJLNpXJRic2AZzK5zBlV5PoxzjId\n" +
                "TiB28gPJ9JASOO6tC142FjxfZzn1/Id4xcEf4WccFfJiQbNMUe9kuIIBfEVLfVco\n" +
                "gfEB1Vo5WblyMPbUWwt+b8xY7wFF2NQpNb8Cg6ebTGqPy9OSOaraNZQ+mLQOVVDT\n" +
                "NqfwAaEY3QoqObS/zoI+aDE/ebim7U6MvWzZU1NZkbWY1ngD0+pLZX9l8op4NjJV\n" +
                "Z4SOoUvhdn5NRdcEqYcpCXMW2ETJnMj9jwIDAQABo2swaTAfBgNVHSMEGDAWgBTh\n" +
                "OA4UGBRDXM7nS2LHGsGS9maC6jAdBgNVHQ4EFgQUhQ2EBOSyja4LSx4MxUG0kb2e\n" +
                "/jkwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkq\n" +
                "hkiG9w0BAQsFAAOCAQEAj32dGQGImnemdjlbIgsR+DypC8tThQ6wED4/9HUarJ34\n" +
                "NJ7yHV3s3GhPyfjGr+WiGgqp6Yo1Prd/epDxbDvdBKfrTV0yDZI/yCYZtZ6WHc9J\n" +
                "x/ThYTx2XyTKdZs6GrgOMviX+ZgpV8147nxK6DKZv5jk0WoshMh7nYh84JeehjQY\n" +
                "UON3XZ5NoiQD57HCUSNGrc0M7pUOK1CQHZzDh9pJnqSbR1sHERVgD8U38bEUFfUv\n" +
                "mweQov0WolmQJmcVuzPZioDeNlhv72gt4qg9gAZEgbQDSyKo72qbcEZ7EMVB4nFU\n" +
                "QOcPMqU0aq6HXBcML7OcgGZQm0iqDJrCpVwlqsaWlA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN1subCA1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 3"
    }

    "Invalid DN nameConstraints Test13" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID2zCCAsOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEaMBgGA1UECxMRcGVybWl0\n" +
                "dGVkU3VidHJlZTExIzAhBgNVBAMTGm5hbWVDb25zdHJhaW50cyBETjEgc3ViQ0Ey\n" +
                "MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowgYUxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJt\n" +
                "aXR0ZWRTdWJ0cmVlMTE5MDcGA1UEAxMwSW52YWxpZCBETiBuYW1lQ29uc3RyYWlu\n" +
                "dHMgRUUgQ2VydGlmaWNhdGUgVGVzdDEzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEAuD/PFvZ4Qii7uYsJkBh3y1o8UCIOhlno/UJa9fVTjh3hwChhv4mR\n" +
                "V2+1yfOib7xKN7694HOCyl/u13ZrsLG7rG/7FcQnZmEd43+1gpinF1Y9QNYv6Ilh\n" +
                "/inHyGe4iLRveuNCzneUH5JcDtklbuaEhUZvVBch9BWEeD/Jp/th2q0ojbFzltMI\n" +
                "3dG2a24zL4BGbNHBdD8PkbfKdE2N9CYC6f2Rd1c0TYdhZ8ZCW2WZ7zUiK70zUKAO\n" +
                "Ng/Bs1VGhaB1DjWu3gbrC+d4z4Q77FN1h1ZPJP5ON/SC7Tf93TWHHXHfWT1lCot7\n" +
                "+abuzyuN6kCKjunaC5tRCaMXGTT5EMEt3QIDAQABo2swaTAfBgNVHSMEGDAWgBSi\n" +
                "L1iDW0yVl7fu9oe0lw7gf+CXFTAdBgNVHQ4EFgQUwJd0yB0ypi+GIJqugHjmrt1C\n" +
                "HB8wDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATANBgkq\n" +
                "hkiG9w0BAQsFAAOCAQEAJv/hxkQtOORch6bfYubBEe1urCmntR2Fj73iIooxcewT\n" +
                "5iC1EPgWR3IluR44YUoWulHhmRNeUqnAtfJYJu5HhYIt1NLXU5yODWJKJ+ZSIUsa\n" +
                "WkFqdPAVp1GDRhDUP4shZC1Nur3gH0wXBQQ3pxsWjwPWNccxF9ZHR7gJxPRPPdE+\n" +
                "FYGeeTyfzpOaDdiQ8Tgihhjh3CTk463nA5XaFWd/7MG+YjnbvGQWb/ag5TZh4yHo\n" +
                "O0Qm5dWFzqyY/UUDV8D2YaDY9DFEk0rpJsfRTCg6fvq+PviGAY+D6uC4YMe3mVBz\n" +
                "+HYIIgOC1OOet4dCoXsgIiy/0nyx5lRU1LSWOCUCSw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN1subCA2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 3"
    }

    "Valid DN nameConstraints Test14" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEaMBgGA1UECxMRcGVybWl0\n" +
                "dGVkU3VidHJlZTExIzAhBgNVBAMTGm5hbWVDb25zdHJhaW50cyBETjEgc3ViQ0Ey\n" +
                "MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowADCCASIwDQYJKoZIhvcN\n" +
                "AQEBBQADggEPADCCAQoCggEBANL44jTyFq7QAleicaquWUZlfqoETqCeRuZqGndG\n" +
                "rpYU1yDVOmaEtITWmCQ22VaIIu7+IaIeFKNyoU0ELLvkWybmC4eI/uI4pFqQgrvS\n" +
                "J+lJbD5jtlLcMNAUf78gd0j3bie97KHei9ipYaZtTUD9RD2CKSdSifI472U5ytsQ\n" +
                "TytctM9miZpgin2XhaqgLIdV3KnrYzXCtYLoegjE8pOTrsYKOURylSDgtJsFwa1P\n" +
                "HRwFQvPhhguTUGB6kkPGCgrqoyV5PfXWGSCvkaN+LrfNIqzL2x6xKoXeY9RaTXtq\n" +
                "t8J5bkv2aI/SxH6x37wA1MiU3zuF+MIlMT2LAs2e+PixXx0CAwEAAaOBrzCBrDAf\n" +
                "BgNVHSMEGDAWgBSiL1iDW0yVl7fu9oe0lw7gf+CXFTAdBgNVHQ4EFgQUXy6VFzDx\n" +
                "TC6AfvMa6q1deaLwOLcwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZI\n" +
                "AWUDAgEwATBBBgNVHREBAf8ENzA1gTNWYWxpZERObmFtZUNvbnN0cmFpbnRzVGVz\n" +
                "dDE0RUVAdGVzdGNlcnRpZmljYXRlcy5nb3YwDQYJKoZIhvcNAQELBQADggEBAM30\n" +
                "T0niDNwc9oxJTmAHuLnIH4LSgOfNAqPC+KqoyjyGmZbsL4bOjpv3D/nvv3cOkuQk\n" +
                "49bygt+lJsDonEKKYBz4L0jnGOZjC3d8UPu80v7nUkB1yzMaZO+A05rNtxA/iA6o\n" +
                "t7N0RsDosn2Fu4q+77Dddx1JYp90XfglW1pXj1gdgrwAMwrweF/fDlAMPs5h2qGH\n" +
                "K7EXhJ5sSToTsEIPVAoLiwDK6yFcCGyui+7koxE0ycDHsDJk0bqRhQVJDKrg7peh\n" +
                "PBbUQT2g5kNNKu8gCB3UQcyn9K9twWAizjW9DNub8L0wsyttyaXJ9k4QMyO4x+OL\n" +
                "E5sd13zm4Tfjnw24VUU=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN1subCA2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid DN nameConstraints Test15" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDvjCCAqagAwIBAgIBATANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMyBzdWJDQTEwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjCBhDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExGTAXBgNVBAsTEGV4Y2x1ZGVkU3VidHJlZTExOTA3BgNVBAMTMEludmFs\n" +
                "aWQgRE4gbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRpZmljYXRlIFRlc3QxNTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK4B4XI7DVIEJPX7gqGREXO6XSno\n" +
                "4X9Z4RamnbW0YiB1VGZeK6xusEN/StHlO4bDt/KfrvqUXJvm9D1oJjPX2rE6By+t\n" +
                "Mi5al/5fCGE9rUov73jyKb4eUSCy5aTHfyjuu5b/ts46WkYOKqGEwSBCQLPqGR4O\n" +
                "YXK5/QSZPIJwuvVJXwEp5/4dv9Fg2WRwRab7EXQfYut7AbQcyb4FrMwGPpja84JW\n" +
                "q5jCvM7EsdmWZXhRvoDrqUtap+aotmfhps67INDFvoL4waIKzrTX2gmjO5kU62VT\n" +
                "78gJfCWE2boB0tUsGGZLyRdvJ8SPbd0eEKykBejqvHcXb51ea205H8xZarECAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAUgLzHLveOGn/xOHv0Nevd6VjGPFAwHQYDVR0OBBYE\n" +
                "FHfYNlCl24s86ePnQaSo5hQFK+GuMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAGqCCsaPWvIjVZbJd4Eh\n" +
                "wY/G7O/cnYbUjVR4IRbj5Ce0lS2+nspJK3D6gqT+DCOxZF6LJQuGOJP6sQUX9OHR\n" +
                "T2oAbrb02A0UqlrpA3s9DtbspM1/yWcHoU9hAP81zVcNq5VNrcdqdFMvmV2MwSiy\n" +
                "+Fvlc6K8QhHxnDaL6kSfdci+C27FWCahH5r2N/1l3Bpou8WhTtjsRqvAgzj2yHRd\n" +
                "DgJhZKMjtieSQkSWQF4yvkUMH/AVnD5xOpSqceaiVFqUFfRSRhHKbtq/eCNZW0RY\n" +
                "i1she5uNHI3aMZS7cajWOltPZ6GYCQ9ovLddg5foIcr6YMaH5u3BYAUCdvMwZeZw\n" +
                "8Qw=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN3CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN3subCA1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 3"
    }

    "Invalid DN nameConstraints Test16" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDvjCCAqagAwIBAgIBAjANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMyBzdWJDQTEwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjCBhDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExGTAXBgNVBAsTEGV4Y2x1ZGVkU3VidHJlZTIxOTA3BgNVBAMTMEludmFs\n" +
                "aWQgRE4gbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRpZmljYXRlIFRlc3QxNjCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANZg8OxefrZytpf0OyjRrUzPyqCB\n" +
                "BZveBF5ZuHB7qRZwF/Qq1v05U23mk3+7fz7oE6xGAgPvNKjktkfflGZI2hRdPNlN\n" +
                "GGqlc2YwMWDwLTmtS0hyyT8Ui7AL0cwHJrDeau7litk6uFOBP6VE7FlUEnMU9ENm\n" +
                "hHBOmYt/tjARDf+kzSle2+saArLbWqBPdMtLtRwD3vTS9Zr+DvccEn2Jx7YiSZDM\n" +
                "tRJaPgoiv+15Voln0E2/XS2fDdog4olDCO5fZ51KNIokMmp+6r55yevXxWxUae2j\n" +
                "ZBLFyfD7hS3NTGDBhCFEry2dbRZb/sXOlPSwKN+x+QwCWBRo63UArRoi348CAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAUgLzHLveOGn/xOHv0Nevd6VjGPFAwHQYDVR0OBBYE\n" +
                "FGC39OnVftLAciz19L+MYPKsjyXGMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAE7YpcJArWSxTC/zSZh/\n" +
                "22a7N/+JOQysAJJ+wKuudXUeN//eiycICbpkUy+hVF9JtZ8Ryy07GyEXm/CMg/Ub\n" +
                "PX1EEvIkH3nyAI6rw13hw2PywCzRabDXwaipbRU8A4dhTh3IAcuQoCcnO4gYVBk5\n" +
                "2Z2Wl5v1jXsCzgEj9gUuZdwLeWqJ2NIQvrOIvauRDP11OcUs69lC7zjJLWgCQ9y3\n" +
                "2UC8nFkkN85P7Mc4A90HcGPJuc1DnPCTvhY5JdXem9/snjVcpa7PTbusyZbrh0X0\n" +
                "inB2hldbyOVTyX4mpUsUW1h2X3rOETdkBHZuLwWRwbyXc01ElGuGnfgihaX1w1i5\n" +
                "BoM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN3CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN3subCA1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 3"
    }

    "Invalid DN nameConstraints Test17" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDvjCCAqagAwIBAgIBATANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMyBzdWJDQTIwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjCBhDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExGTAXBgNVBAsTEGV4Y2x1ZGVkU3VidHJlZTExOTA3BgNVBAMTMEludmFs\n" +
                "aWQgRE4gbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRpZmljYXRlIFRlc3QxNzCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMP9rpCat1D5Io1BWYqPNBT3HkkQ\n" +
                "+k2vKuqHt9zXif0WRtnmGzqUvpy5crHBlToyawqJQAMVPMt5W/gTJrzzV+Bf79+X\n" +
                "yetrlM3qs5n5eNfIU5D897S1AEfPIkRdjR9kdL1xZYkDZrEBmFHgsRS9TDK+01rt\n" +
                "aJ2qOKscJI1z1ngZUZscSLwCwznvw44W5AP6WLxX+g0ERBsNRjakWQS6JlWgGvn5\n" +
                "oq5PYqnrIh7TgtGgjL9jVX+xbz8lg/f5iLwbfTw6SxGMZV+89jrMPHjW+58NMUDy\n" +
                "2kn5W7B6eUqUOA2Eb+oYKWLujNqYeaoUZa5TUBo2iUV9WnJ4ndiMHwzveOUCAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAUzATtaigdft5k6gCIKux1Eb+lLmcwHQYDVR0OBBYE\n" +
                "FBFLTj7lB0xsW4f9PPb1I2VfHkVqMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBADjr4s6VekQmcVVddOQH\n" +
                "8wbIQNXHEQINEtlqUQqaCE+wlszME24sKPs3qMNEuVyQVFvwZdpnPXF7/oSxAyMw\n" +
                "yO/hzSGcJmBEd1VvlabY0IJ/PAy5vq5XuQk0sWbWRAOF4bcgAdn8gH0vCX+6+ajC\n" +
                "o7znSglF/G0vsEkaqPhaUk7Ookee59hpHSKOOqhp/f82/BFjrF6lo+AJcRKqj3rx\n" +
                "aMckYizxJ4+pLPEtG7shS5KKZsz8PW6DHDhJpNe733gSKU4wx/Lf9BNBRdlKmnqo\n" +
                "EmIG/lzkZWwd4kh3/CGOko7qTLcLQy3ARHRQg6z+8qhmtTySJriamAHL/3nIFKCx\n" +
                "z84=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN3CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN3subCA2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 3"
    }

    "Valid DN nameConstraints Test18" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDoDCCAoigAwIBAgIBAjANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMyBzdWJDQTIwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBnMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTE3MDUGA1UEAxMuVmFsaWQgRE4gbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3QxODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMCc\n" +
                "FAieQeWV3r7La3dUczH3NGDXPJiaAR+Tqn6f8k320kCvHGdaBRcTKZXH4tX3ZmE6\n" +
                "vFn8l8xfrX4ApA7+GPrM0MVIUJsMbw3CGjoz872d/Kgz+vS6idpGClTvihDBL3/5\n" +
                "Nt3TSxejRtxyHVfrIv+zN7f4OH2dZVzdi7ygCv2Kd42XegPi0DKGCdC+ygKWxsta\n" +
                "0Nti3GppDzGF8UElao99zalmEtdeLgD00v4w0kVGwmmFMn10JhKdwmT2Svu9DteY\n" +
                "7jum4YaB+yK9IzA/j4Pr0I4FyOC6ZdJNdyrFAU7y5G/eTziM22YEujjzbe5P7X1G\n" +
                "AUenUiC1R9eaFoHYH78CAwEAAaNrMGkwHwYDVR0jBBgwFoAUzATtaigdft5k6gCI\n" +
                "Kux1Eb+lLmcwHQYDVR0OBBYEFLQCkqHPGqp0V/N8OEcO5zUqhdd4MA4GA1UdDwEB\n" +
                "/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBAFImhmXh6wbcMuY4ksQzwV9ci+PiOlD+x7nQddqIsuj2CtmLdphO0z+jhw/c\n" +
                "AcLQiIUJEE2UT0Eow1wYT3IsGV52jV9Xv+4Po9KVIA1S8W87IFJlBhkXPvmzmSeY\n" +
                "KwHVKq/4fUXpy30yvfxGEWxG3HUKHg7m895xfM2kiKb3RnmC0+FmZQayAi76WaLF\n" +
                "8u17d9hZo/cLoNd66TyPuxisLiqbXe3Uzvorkbd1RYlwBZUtl+T076+XCluS5ZL4\n" +
                "Fu5vN9C8+fQWjsJnB1/ifh/oiZqkSkR9K4s+0qAKGOTcrMsf7OfiybRIfkX5Mhc0\n" +
                "KyfioCAyiP1/9+WcRhdt/NLYheg=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN3CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN3subCA2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Valid Self-Issued DN nameConstraints Test19" {
        val nameConstraintsDN1SelfIssuedCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlTCCAn2gAwIBAgIBBzANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "ME8xCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
                "MR8wHQYDVQQDExZuYW1lQ29uc3RyYWludHMgRE4xIENBMIIBIjANBgkqhkiG9w0B\n" +
                "AQEFAAOCAQ8AMIIBCgKCAQEAyiKAFzYtdvEdciQ58kyp4foxdHez0Ho0jlCiy8aV\n" +
                "7EdOkOe6I+BAIve44XQywvh4JqZ2xEkYhAFuVhZTpe419Fojtut1pS5p1MiP87y2\n" +
                "eJ8jRJFMJ/O+UwCRwgt4G0whBAO10BT8ETwD7wkl5XbF5Q9cj3oB3ESyQC4klN5y\n" +
                "L5lcnyMUqZ8e/fmiJD/M4siYIAUqJzfYpPgExDfxCc8Y5GolybvhVlngHn3mqa/l\n" +
                "qjfkIjqVbB9qSEbS+vyrZp4+HFKeTxCNMri1UeRYIhm30XIEFVD/c8Z/e8FqykQH\n" +
                "ZyBeEpwb5caoS8+sPcQ9DN2afMEHfVCZfXyL4P3Gj3MANQIDAQABo3wwejAfBgNV\n" +
                "HSMEGDAWgBRBeEJGzU6ogufhOd/3qRbACvzvhjAdBgNVHQ4EFgQURZ0b7sX/48TH\n" +
                "MDhMW8ddVJlywLgwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUD\n" +
                "AgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC0BCN3q3RD\n" +
                "IGoq2eKsryXDduFqAJca6+jKE4re+Kmy7PK4f0C57r6za/KQTw3fDgAKPi6DctN7\n" +
                "BoXiEL4nDtNE29OuuMPMQmpyZZ5MF7H8ZgRrzYW3OMbu48lzwcBIZ3eCPY4rL6uM\n" +
                "OaBRw7TXMmFVnxsusN+SB0o/FXIslyKijV5ZACP1Bf0OotzZnsiWEkGKP2H/iDxs\n" +
                "+rxLVYTyowtKi4EmA7M2a+2LmGvndpB7u0KghWDL+sKjVa4PK2r/9AiulLL+FJbY\n" +
                "x0Tal47siI1yC2P4XXj/8z5o8jrYqJFY8QNAl7PO2vNzo6CqXF1QypNAVeDYYCcG\n" +
                "ysMMqgXsj7XQ\n" +
                "-----END CERTIFICATE-----\n"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDuTCCAqGgAwIBAgIBCDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "MIGDMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEaMBgGA1UECxMRcGVybWl0dGVkU3VidHJlZTExNzA1BgNVBAMTLlZhbGlkIERO\n" +
                "IG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTkwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZDEN42s2ft+DCcNTzYyJbruK++J4wlPXY\n" +
                "3JUK4AuI7b55n28caZPvcvtanXRwoQBbvAp/ub04TWtx8o/8etTSciTIBQ6YN0qt\n" +
                "sh2WW+zsppqt0C+c3Fc2wJJcHh9VQzdMo74pn/mqULaS2K2FQ6msHaplTXcBILHA\n" +
                "g78xjSQG054NSxqV6z+AsNy1Syw57a92XbmPjeOIsA0oRaHDZfAG8QvQxvWdsh0U\n" +
                "oyCAM+8IpsSuNOGBpCDViAM0pUuxzeG1WHrYxvyGnQsjjj4HqUqrCXUNWL2yHyD8\n" +
                "gUv+sYtecxNG56/UowvUeK8eseqmn6BTLur8FC7JC7zeM9ROiEkFAgMBAAGjazBp\n" +
                "MB8GA1UdIwQYMBaAFEWdG+7F/+PExzA4TFvHXVSZcsC4MB0GA1UdDgQWBBRZQxHX\n" +
                "4rWSiri1Ka3mWvM/NDr6GTAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQCDwHY5/eYX9EpSxTjNmRXVJjje\n" +
                "8HJ+wB+U9OsMSk7tQb3vsR/ZrgWJXdHuSdaFYUxWDFh6Ufr0kI+AG0nn6V8Kiwka\n" +
                "73XcU5u9OURprhay2gw331HAcdM4v5Hlv2TQuhFs89MrdzXJ7DJlv//cVg+RTN/9\n" +
                "OqonUDT/30LUPs90p3PhCBpR5rBqVPX8lzpv849lGQ+eSsdlYd/TG8MM536ImHIj\n" +
                "xnVMqB+1VlLj77W9XgrxrcdQIBFvAME/oUs2tix9cAbe0+szHinaI46VWCRdkJ/q\n" +
                "ONNx6C0yX7KwAv5ksINxW7Sy9ajkliArvuq8AfaaO+aupYabnhiqlhF72KF9\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val selfIssuedCa =
            X509Certificate.decodeFromPem(nameConstraintsDN1SelfIssuedCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, selfIssuedCa, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid Self-Issued DN nameConstraints Test20" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDhDCCAmygAwIBAgIBCTANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROMSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
                "ME8xCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
                "MR8wHQYDVQQDExZuYW1lQ29uc3RyYWludHMgRE4xIENBMIIBIjANBgkqhkiG9w0B\n" +
                "AQEFAAOCAQ8AMIIBCgKCAQEA1ExvqY+GA/Rkxpv9Ks8KcNqtdknXm5idOg9XrvIe\n" +
                "d8xy9vkyIs8iZbBgoOI9JI2mhabIchnw9ALe+XFtKL64UEWS2dTH8EqhLgkoIfBB\n" +
                "B8kHZhNaiUxf6kjvOx+/H4TWeTws9iawctciW2FwmmP4G4bZlBP10tZFAspJj/fu\n" +
                "UWJ4rZn4jks7qHNpUOpZw4z8Q8Xf7cKLLSloCIDIJtyUxpM2bT/fC5w2Q6Z3MmKQ\n" +
                "BMi38zWscyG7z7zy6ceYyRBlG5xRsgCYUsj5sWVvtHn3uDpJ6XAW27Im3YxqnRuA\n" +
                "R7fO/i4pNX2RZpkFuJhQ+CveyXXvj0loAbcyDAX8OcbnHQIDAQABo2swaTAfBgNV\n" +
                "HSMEGDAWgBRBeEJGzU6ogufhOd/3qRbACvzvhjAdBgNVHQ4EFgQUWEq64IDyyEM8\n" +
                "lrIC90qylY3WwjMwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUD\n" +
                "AgEwATANBgkqhkiG9w0BAQsFAAOCAQEASvXlo2YzLidKbhlVkkfFsdclc0NAn1yT\n" +
                "YgVEgLpFixmVilXQqH4lX1cZ/wkFljd90H7VUQacMnqfacLOyJyHLBhxA1kBv+bG\n" +
                "bERpTDveXwmBgNxs2uMinO+EbCEZbWdSrALyUyLrJUaiqVln/m9gtA3tnLJ6/9lS\n" +
                "uHcZ8uYHjZC05SQOgCp2GI6yo/nS0Pm4D9Z6Ljh676Zoc+Xqe8mbOPUdCNfnv/xS\n" +
                "6jIIN7HtRNLUWlrq0RfT7T2oOls0lVX6vE6tunEwh5Nqw+aHLFcQNRJw8nqeoJ3o\n" +
                "+1t4936HAgpU6H9+qejS3qXKnGSalhyEZF4B7YIjMw+QgMq1iy3FDQ==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid RFC822 nameConstraints Test21" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID2zCCAsOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIFJGQzgyMiBDQTEwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBrMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTE7MDkGA1UEAxMyVmFsaWQgUkZDODIyIG5hbWVDb25zdHJhaW50cyBFRSBD\n" +
                "ZXJ0aWZpY2F0ZSBUZXN0MjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQC5yv2YRIEhQf1yjI/+8BH9zoj+WkwrpoJikq3h9IAR3QF1b73DUngYZizZoxi4\n" +
                "zFK3hJIaln6yaq4VLKImcJzGwf2H80nYKD+cKEo5vFiG9qnm7m6so2sUDT5YYW1w\n" +
                "rGHDO3qJNlzF3R9cM4Fm/hi7UpABHwWqJ4wApX/HkPg0DQ0JXsgnCS4vr+uIgCbY\n" +
                "m762QCDH8YvxEDWjj/xy/BhCVb6Rzb4wzJE9DD0+8+Zr3UVKhoPQWsNT68JFLUd4\n" +
                "t8lMndnhGqQj01atU4lrq1T4bXO4USw4WUYM1Eh/9KvTfRxBlIvrWkEe5UamC1nT\n" +
                "HxlrUqXfSg+69bXgh89wKqCTAgMBAAGjgaEwgZ4wHwYDVR0jBBgwFoAUyGqOsQ9L\n" +
                "qqWIuKePkdvqM0ro1eIwHQYDVR0OBBYEFGYJoy8FC+jXyi0Q7O4CokLJZ2PUMA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwMwYDVR0RBCww\n" +
                "KoEoVGVzdDIxRUVAbWFpbHNlcnZlci50ZXN0Y2VydGlmaWNhdGVzLmdvdjANBgkq\n" +
                "hkiG9w0BAQsFAAOCAQEAPS+Re8+Y16TsC07sv0TLKtOFqh3WUaKg0drF7pmruJc3\n" +
                "xmc9ACF5aBvAOGA/4cVaVQ6qEtA42TcqxRj4RJynb2p6Ay4DAVRYnWYeYH6rjFOH\n" +
                "a3xE8zXCrUUGpnYYP27plJMDhaM/uR3NUo7Tp9MagVqv/Iv+RUUQi7Hj8vWg5J0q\n" +
                "ggpJApU8GeqyPsU81Hh4ZXG9go1iQN/QH7p1uYpf4OImMTfsE6RvV1UXNX2fiANt\n" +
                "1XrEyeYyCl0LEdoo/+vZmEj7XuBpVTHTdFtGDfnzzWyLg4K0J+1ZIsHXtivhnrSY\n" +
                "aM5R0nE7+ziQV9S6U/zR62TrkQ66aMoxzN4SHgYD2Q==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsRFC822CA1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid RFC822 nameConstraints Test22" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID0jCCArqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIFJGQzgyMiBDQTEwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBtMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTE9MDsGA1UEAxM0SW52YWxpZCBSRkM4MjIgbmFtZUNvbnN0cmFpbnRzIEVF\n" +
                "IENlcnRpZmljYXRlIFRlc3QyMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBANL6mw8zfZFK7YonjGlE008qAPEdOsOk+EExeugqWGTUCv/Dq74SUVM5jDWf\n" +
                "CsQtfPc/miyUEvcl5ep3fISwLriz3lSSQW3Qn5RzYJdpA5U4ahg4FKqMjNTqt9/2\n" +
                "VAEsRiP3tdsyYREY1G0QT9ROpN95Cr6siEm2qVa2r4iPApydbxxYr2yR4uIk5HsY\n" +
                "IZ5gnJvnrP68ibAoKrhVr0V5Y9bhsYEreS4LpBpHGwidcrN49vg3WhuRNFVhCNz7\n" +
                "qgfAU2vnCJdWsE/4R4rlhmlm7uvorkDX2++YoOMKxS8Q7OreLzMHdDqAFMtjyj9C\n" +
                "N+FEQZBku2asKYHBehARSa8nCL0CAwEAAaOBljCBkzAfBgNVHSMEGDAWgBTIao6x\n" +
                "D0uqpYi4p4+R2+ozSujV4jAdBgNVHQ4EFgQUz4Q/P/5DzDB2OPkED44YfyyeisEw\n" +
                "DgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAoBgNVHREE\n" +
                "ITAfgR1UZXN0MjJFRUB0ZXN0Y2VydGlmaWNhdGVzLmdvdjANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAAU/7LeKzJxvHV8Z871YW+xG1i2nsULXHrweWhaKU3u6L7HYNxvZJSHti\n" +
                "9vhgqOBc8JyyIvu8GUCyqED7S0/VDalPwCysrbAJDNTfgxx2amlOp9gb2LBgpMVv\n" +
                "EROwfwFsZhl486M57w8qK/PvRuVFDhm1+QhDm1q7boTU4+az+9DgX+UjBtWPPYGq\n" +
                "nAMyH/0X9Abmkv7Tm9egKtVxe3ScjV1P0Ti385LaUVqIekrxjItWZIU8lMBgsbXV\n" +
                "1jA3HKOwHNJGyL8D0TnoF/8Q2GRA4j747hHyz4bkSxnLi/GwTLb4ldEab87vzzOp\n" +
                "tlNkycHkL4+iAMH1ZBHG5CnoVVmg6g==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsRFC822CA1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid RFC822 nameConstraints Test23" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID0DCCArigAwIBAgIBATANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIFJGQzgyMiBDQTIwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBrMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTE7MDkGA1UEAxMyVmFsaWQgUkZDODIyIG5hbWVDb25zdHJhaW50cyBFRSBD\n" +
                "ZXJ0aWZpY2F0ZSBUZXN0MjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQDH97Obgu2TXLwsB+kAldNq3ukQyHc30y36W7dtTniOxGsEMu0pAGqDCLjHvAcM\n" +
                "NnebR8UQCYbwW5ooli8mhSBwbic2vrs4ox/Zm1wSePT4QlcIme4mru3mL4cDx9jK\n" +
                "gaRBsa3pOtanpaT2pcK+9PK1RPJiivhLwdBdg5u8TQ50te+QJpbveTyNEP6fd2d4\n" +
                "0B3ebPIGwxnAZ1OJw8V3nbH4yrGsxHebvPkTooDkTVOW3OkWG870k2m4UgQTs0bK\n" +
                "Cr6nfMZLh9UHHHSqkhKPATYBUEC78qGG+dJCYmv2ufkdD5Y53WmcI7I0ox5MDBOi\n" +
                "PProYl1M1eoY3Djq1G522kJpAgMBAAGjgZYwgZMwHwYDVR0jBBgwFoAUUYDN+kly\n" +
                "SDztDk4Lzs4fQGUScKAwHQYDVR0OBBYEFBekOG7BL12uA/XHxR7u1gLCDUlLMA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwKAYDVR0RBCEw\n" +
                "H4EdVGVzdDIzRUVAdGVzdGNlcnRpZmljYXRlcy5nb3YwDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBANk0lkglDUSef6Hd7yu/Gqplwo8xx3HVg9x/+T2pIKeK+hd+K97gt0ZEzjjw\n" +
                "5ul4LabIQFLS2hpT0F1jc4tjfh4pITMW6LAUzAae2LFbHguO3nb3X7/gSP5Bm+7x\n" +
                "Ppk9eZHoIDFqKKnXbzezK/GOIjnK4zr1u9xVOqFpjwjVgXdvQ1EvjydJwrwcygEX\n" +
                "u9OY5AUCZ2I+cT3K10Ms+bnupLizv7HCcQuQRLBd0B55z5MtiBhwiju8qJzxoX9V\n" +
                "hUmOVgSzYdLKZRPlRHzNmZoE3wi5cg+8nIZXyk/+CrZGrbN51P54RvbdDGohocln\n" +
                "egEMHQLtjaba5v5XxfpHPn+wqyE=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsRFC822CA2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid RFC822 nameConstraints Test24" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID3TCCAsWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIFJGQzgyMiBDQTIwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBtMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTE9MDsGA1UEAxM0SW52YWxpZCBSRkM4MjIgbmFtZUNvbnN0cmFpbnRzIEVF\n" +
                "IENlcnRpZmljYXRlIFRlc3QyNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBAO3QrhcrFnARNcuvNoKoiR9dNECwpiyjNYIMkr/sbcZQnnDHLTX+KgQf09Mm\n" +
                "5DI6sXWmBwFlZCJYDP03ntCXO5thnb9X2fU5eYlsKivE/gPsasDXYjBCkhiztSzG\n" +
                "n8P504ZOy/lfnn4AryvauvAnN/2PjPCoysWp5hUmSotCCbpu7i6MyLdjVx1slPbg\n" +
                "W+nIthsZGIbo/6n4eXq70D+PA0fpnS47DLaT2wgmveiXE+493ilAE8LcQqhcHJo6\n" +
                "Pw08KQtPo23Fpf3o3Kh5QWOPm8lw4AAE2A7btkYJr8LsN8hYF3EApmEjFelHI4wW\n" +
                "3OpRe0FKh6l00rZzmWyrwom8nrMCAwEAAaOBoTCBnjAfBgNVHSMEGDAWgBRRgM36\n" +
                "SXJIPO0OTgvOzh9AZRJwoDAdBgNVHQ4EFgQUjKQ6o0y35k1d94MC6HLB+wAbONAw\n" +
                "DgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAzBgNVHREE\n" +
                "LDAqgShUZXN0MjRFRUBtYWlsc2VydmVyLnRlc3RjZXJ0aWZpY2F0ZXMuZ292MA0G\n" +
                "CSqGSIb3DQEBCwUAA4IBAQAw+N6NgtahpWR9GAlOpTU6BDQ1jAUlL04btBcufBrr\n" +
                "6QCBibzNfigkYBS014FyJ86qCj7JoRLjzyYP7C6PE3tKBXklxB1hwoqE6CdLL200\n" +
                "amMPsWfORjIBp5vSC1m99pPUOVyxFJSFV4oRZQ752AoXEWXJj7qYlqL+3hdNdxjH\n" +
                "xw1UQQITlsEYmPJSmhh/HrBXNB6+5rRxyu0uYo3y3f1B8khq10wSrQV5pXj1Jowk\n" +
                "oZjjqd/pMUWWJU7UoJom9FdwKUZ9hhfEwL8pT75yVgZLvqoqGsqR/o3ni1NJ5LK0\n" +
                "GST2v+jrlvs4riCqbFPRMk70Ix6UOoO3Psv2urfsxTx0\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsRFC822CA2Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid RFC822 nameConstraints Test25" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID2zCCAsOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIFJGQzgyMiBDQTMwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBrMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTE7MDkGA1UEAxMyVmFsaWQgUkZDODIyIG5hbWVDb25zdHJhaW50cyBFRSBD\n" +
                "ZXJ0aWZpY2F0ZSBUZXN0MjUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQD14E0HjPDPTkFDMDJGgWqJtdxDgR9z+/bmgopcNwzghAjljVUrFEJ/WIiwcqty\n" +
                "QonLqNdWtdXrI/0ZuAEhEohgCTIv6xqlhVmryx8w+J1N3Bg+fTlhymbihunTV7BG\n" +
                "8iGjnecbPaMJ0H5Evgi1XBruq9ALU5UHsujvPcRnlJPToOe5K1RSdDK2trDPfxMV\n" +
                "zapzN/pIPSnuZvjPiF1TaRI5fEd8yNYhyIoDYU+W4ZCbqOhTmBUGnKde1dNWtMhH\n" +
                "fFLGWgbbTt94ZK1oHAHAojeWL/bC4WZn7xKYvf4loyiUUPvL9Z5LL7cFJfH/ww1/\n" +
                "N7ZzlE2Uln8y2vJyg336IE5lAgMBAAGjgaEwgZ4wHwYDVR0jBBgwFoAUmro5Tdoh\n" +
                "da/qQcM8bFHYqEWpf6MwHQYDVR0OBBYEFCSLs+Nanik16QFtO2bqOxm18KTbMA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwMwYDVR0RBCww\n" +
                "KoEoVGVzdDI1RUVAbWFpbHNlcnZlci50ZXN0Y2VydGlmaWNhdGVzLmdvdjANBgkq\n" +
                "hkiG9w0BAQsFAAOCAQEAXCL3x2CoR+4+uBv3/rjM7X1cWiSc89+ydAsWHOVgHpI2\n" +
                "nnxYPijuJTyiINCNQCZ2xReOMbd4IkhnaKt81hThsHlulDhBc7j9d29RfkA3KUDj\n" +
                "QpIWZaBJHhe1668ETpOw/CHBPGfmPb7GhCfL9wZxeqqTytfgBhXHVd+W+ZOlGUPk\n" +
                "8Ag1yGqnl0gmKXycSTR5uAAQvzwEz9QM2ZOMWF4N7WVEZMzm1mtZyWlI0MOzEEed\n" +
                "A0j4FLWEkNh+6wf/wQNpDKNSipLnRXqE78IhKqBG9cR8+PDIjexXNCSZ/FvgU0k4\n" +
                "PrbtJlt1IBitxYNFyXkq5W4p9jeG9li0wTktImmm3A==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsRFC822CA3Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid RFC822 nameConstraints Test26" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID0jCCArqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMabmFtZUNv\n" +
                "bnN0cmFpbnRzIFJGQzgyMiBDQTMwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBtMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTE9MDsGA1UEAxM0SW52YWxpZCBSRkM4MjIgbmFtZUNvbnN0cmFpbnRzIEVF\n" +
                "IENlcnRpZmljYXRlIFRlc3QyNjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBAOPaHJrQm/Kqqf/4/xBLsdQP9fekUUNe2JiuIA3XdwLgabu6paTFdV5jVcR/\n" +
                "imqnAWJ8Wx2IBlfy6li6la4rhHrc0aU1T2mmiqXcbFyxnslvKsPTOevBh++PfbLx\n" +
                "zP+NkPl8tA6W33/oLnCQsDBYmqdZiLrjL5hZStWAq0YugLKE2HSjRorXTRT6Ged9\n" +
                "xwawSrbCsG2RRP5+jJtvtu/AhCjx+75mVBsBinhlDN10/7TNmwA1hYNQ1BBiszxZ\n" +
                "PuWkI72jCjsJtI4uG5Ds9B4FzWMLjCRMS/eCO4/wX3WbeQHzHsTbPg+qsgo4kElv\n" +
                "XvInxXNc7ZJH8UC1WfKbryDd4L0CAwEAAaOBljCBkzAfBgNVHSMEGDAWgBSaujlN\n" +
                "2iF1r+pBwzxsUdioRal/ozAdBgNVHQ4EFgQUImSefsikOFzboCbTld2bd2ooI/cw\n" +
                "DgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAoBgNVHREE\n" +
                "ITAfgR1UZXN0MjZFRUB0ZXN0Y2VydGlmaWNhdGVzLmdvdjANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAXr9hF23UlbewDYWKUwzUTOrAUaEQ3SiN8f+D9c0bX0S61RUZWDcsiqVb\n" +
                "pThRuIamdDPEPoyxOSJOGNHKJc/mIixymmnjDRwSCho+FvbI75T710aOecpmrQ8k\n" +
                "IymBEXfebP9GXc1jQxi0tDKYpv4avAz1zMnKs4JLxiUYftwiQd99JizQKnG9bqsS\n" +
                "M2Ogn1QWsZRzW/YZD8i4k69WQIV/a4M45b510y/qHU6T5U61JO/EXiEJPxsjOwta\n" +
                "W613Q0ow022r4b7pTyU8gKyDgi0sgF6k2GL+cD9Q0+rcFwT8w0OQlynq5yM9n1Dp\n" +
                "gHWSV1lpJjz1R59LX1j77NESaDhDyw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsRFC822CA3Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid DN and RFC822 nameConstraints Test27" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEEDCCAvigAwIBAgIBATANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEaMBgGA1UECxMRcGVybWl0\n" +
                "dGVkU3VidHJlZTExIzAhBgNVBAMTGm5hbWVDb25zdHJhaW50cyBETjEgc3ViQ0Ez\n" +
                "MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowgY4xCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJt\n" +
                "aXR0ZWRTdWJ0cmVlMTFCMEAGA1UEAxM5VmFsaWQgRE4gYW5kIFJGQzgyMiBuYW1l\n" +
                "Q29uc3RyYWludHMgRUUgQ2VydGlmaWNhdGUgVGVzdDI3MIIBIjANBgkqhkiG9w0B\n" +
                "AQEFAAOCAQ8AMIIBCgKCAQEA4YwJBaWuiNbOXsrZHR50iYNo/KP34QUkqySEdyVQ\n" +
                "XRYjgcVtLO5sRCeH16qBeglO26DxAouS1ofdzD48hjMWLKzNwAumWmrQhkhtUQhP\n" +
                "EA2ABxV4rFW2fKm+jjWmPNxhLWceJED3XEnY04pHfy83gC8YDgPQeqRn7gEdQbaf\n" +
                "tgUT5/yzBii6idSbJwWwNtMho6/6a6DabRtdXlz4h0hg4OCPU6aPUuIEa+wupnnZ\n" +
                "ac1Rl+XSZI9gt0jEMh99WDpi15o6QpItW/aPxiZ6uokdAds0DEEik5JsbGRSzLNZ\n" +
                "JbiLV5kOQgtzyj/GQ4HcigW0k54UQWx1kjj4YwsgYvpOTwIDAQABo4GWMIGTMB8G\n" +
                "A1UdIwQYMBaAFCdJ5ATZRfpsmJRs/O0NwyRSbVVEMB0GA1UdDgQWBBTRTIBGyj3H\n" +
                "PjdjTstrMzXkvcN4pDAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgB\n" +
                "ZQMCATABMCgGA1UdEQQhMB+BHVRlc3QyN0VFQHRlc3RjZXJ0aWZpY2F0ZXMuZ292\n" +
                "MA0GCSqGSIb3DQEBCwUAA4IBAQB5K5dCXwefGo7l2SB8szQesEoMosZISkK5QRIm\n" +
                "xxHkPMc2snn61jVFDOVvL8muOL9hSNPBiOHBNnXC9mypo14FEfQRI5FjLm8MViWp\n" +
                "doY5fn605DBnB5Cpn0gcwB/MlPe/TDbCVVON8/NNqWqyVZ0y24wF6LLjYaHR9QmV\n" +
                "zdlMfljjO/gJVNxbhad0GL5IqMTjkUgAIC0z+ubj8M1BJb2qdIOk1v20syn8r9at\n" +
                "iN/+SBwawEpSfVR7K+GIFL4xSjPCqHytmSMMCX4HkGlCw5rlJulusIvt2tc97Npc\n" +
                "v2KJSeZ81jehHBt7sUVqV/DgO2XIrysN5qKcD3nZs59qx5YK\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN1subCA3Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid DN and RFC822 nameConstraints Test28" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEFTCCAv2gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEaMBgGA1UECxMRcGVybWl0\n" +
                "dGVkU3VidHJlZTExIzAhBgNVBAMTGm5hbWVDb25zdHJhaW50cyBETjEgc3ViQ0Ez\n" +
                "MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowgZAxCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJt\n" +
                "aXR0ZWRTdWJ0cmVlMTFEMEIGA1UEAxM7SW52YWxpZCBETiBhbmQgUkZDODIyIG5h\n" +
                "bWVDb25zdHJhaW50cyBFRSBDZXJ0aWZpY2F0ZSBUZXN0MjgwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQC4vbpQh0jJq3Nji3nx4Sfd4a9Ek4bG4H6jLwpj\n" +
                "rsy/shoK6yz8nnXe/w8ZSIYH/pETrz72I3kEz5/VI6rxHf9Qo+lqLURImkRhxwSc\n" +
                "ylpDPcbu6LApCackMGAms8ocHu+g6ZELzg5ubrcfg7IcHjnZMdUjXqEWptkZf74X\n" +
                "cDGjkJtpA1jJgvEiwSy5A2MkBRkf51/4SGxpN0tbnLyW4P9T4s9p0ZECanXijTK0\n" +
                "px8Ln6lAaV8/mwjat4G1WzpMsiMKYkzD7dC4uSunEY+1+M0NOsiWJwxS8oIA8AcF\n" +
                "DOzTjx9WV8xeofZeY3ZJQJyJoCI+L70s+/9dwHxeXVbBbkGbAgMBAAGjgZkwgZYw\n" +
                "HwYDVR0jBBgwFoAUJ0nkBNlF+myYlGz87Q3DJFJtVUQwHQYDVR0OBBYEFK8MG92q\n" +
                "3AJ6cZcpow9Tp0emF1RiMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCG\n" +
                "SAFlAwIBMAEwKwYDVR0RBCQwIoEgVGVzdDI4RUVAaW52YWxpZGNlcnRpZmljYXRl\n" +
                "cy5nb3YwDQYJKoZIhvcNAQELBQADggEBAIZk5m0SIfQF5ZF59PLUTrwGaG3jiJKm\n" +
                "+IdyCCM2JsVcKiJ/DoWkU3Ao14nmJkyjAFG3HoYqap5lxKyWpwvmv9VzBGmvJun5\n" +
                "v38Z6zVGWSAKMt/w4yAJBVWWaDKHTP4nfBBYX8uAKmAewlNxn4LjWuZ3AWKfbuqx\n" +
                "ve0yYWP9wBs95PlW47j9ky9uYjwAgXX3z4XnG3NkOH13uxPI6ZjBCdacVuIKDVZt\n" +
                "3pqzHcBT5FV+9JrwvPxnaIauRpb07aWopvcl8vUF5Z2ndZjtBIjAtlnH8AHo3dwy\n" +
                "b1v4tBbIjYfNUSlCtBjUC2SrlX0AiAqzq0jPL9YBiT+E0VnjRaYHmM8=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN1subCA3Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 3"
    }

    "Invalid DN and RFC822 nameConstraints Test29" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEFzCCAv+gAwIBAgIBAzANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEaMBgGA1UECxMRcGVybWl0\n" +
                "dGVkU3VidHJlZTExIzAhBgNVBAMTGm5hbWVDb25zdHJhaW50cyBETjEgc3ViQ0Ez\n" +
                "MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowgcExCzAJBgNVBAYTAlVT\n" +
                "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRowGAYDVQQLExFwZXJt\n" +
                "aXR0ZWRTdWJ0cmVlMTFEMEIGA1UEAxM7SW52YWxpZCBETiBhbmQgUkZDODIyIG5h\n" +
                "bWVDb25zdHJhaW50cyBFRSBDZXJ0aWZpY2F0ZSBUZXN0MjkxLzAtBgkqhkiG9w0B\n" +
                "CQEWIFRlc3QyOUVFQGludmFsaWRjZXJ0aWZpY2F0ZXMuZ292MIIBIjANBgkqhkiG\n" +
                "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnoHPUN2bg6yLDHBYTGVFhMWB7jFvgUuh1geM\n" +
                "i3nK4E4UqszjE3nm6YRJDExcfBRCPuH4NoiF7aQtOXqAP90h6hY+6ikQ18WZDx07\n" +
                "1FxSDTqwSgDpNS3UyheEDvTyD9d5GpcVasvuLmQ4ITibTT3GHaGcV6Tg7jwif3lY\n" +
                "6GxNl73YoOzscwtYuzSNmVerlrUAoy+w5LhLjuwWxPzeoaUHayamLXipBwiaKLWL\n" +
                "4WYr/S7rNHz92cHFzIHjF3bQuFLpP9r6El3MDfZbXmu6K5vj/LDGKcOj1gCHbIC5\n" +
                "GZIW0tbPxuMfLh4CPZfsrpGw7Cw+fnTocUPTv1yasn46YzhA1wIDAQABo2swaTAf\n" +
                "BgNVHSMEGDAWgBQnSeQE2UX6bJiUbPztDcMkUm1VRDAdBgNVHQ4EFgQUKqooRqSK\n" +
                "ejekpkSf3GDoIwRd8JgwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZI\n" +
                "AWUDAgEwATANBgkqhkiG9w0BAQsFAAOCAQEAIJzDlmebZhMjzkhP+mOudtaSDpex\n" +
                "GaQjDFetxOQ84CcVDofcsMoxWqRv/DRBHd3YfY90nbRpxNVPx55/C8hjYugK+KIB\n" +
                "tY8JfMZrLY+nb4Ol2IFdPIDBX129nKrpaudrRE7onKdCAmfneGQfZIA4Hy7PozB2\n" +
                "I0AscYOZp+e4F/0YBo5iaO74fafllHCN5nj3WL5+hRcghhvTaOrmTea3D14OIl17\n" +
                "wn1aIdclzOQoMu/SQUXuwflUDDbDHntudZBpr9TTtm0M+fuAYcJvsXdrT0PfoQSj\n" +
                "BpV5kId6JE3tjhsIc0e+Hv27Hrifq2xQAIonuOgqlDLPqlTHeoAgofv43g==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDN1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(nameConstraintsDN1subCA3Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 3"
    }

    "Valid DNS nameConstraints Test30" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDzDCCArSgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROUzEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBoMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE4MDYGA1UEAxMvVmFsaWQgRE5TIG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZp\n" +
                "Y2F0ZSBUZXN0MzAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE3efE\n" +
                "Ew9OTIYxe07PiuyT1xASI18+bk+gPhFo46a4GTv1BYJLzxKlWNQkeb2yHNhHamis\n" +
                "09o2kHi8KxtgvEQpSItGO3orpoTNx/ag7GZ+uT7pPQX9NI8HDYaaHbU86E5Gf6l5\n" +
                "xbFV+g5uVIJY1MKV6N/cJ2qAg3o1/aJOg87sXW0q7Xv3QKXbmzlRwVR38QrSRgdN\n" +
                "r+BIcZ6r9plX8P3ghHH+/xHRfilCh7FWmrruGf0K3w7gudE0RjMTYm7zHOny4fs2\n" +
                "W802lvgWW0Kls51YiqdjmT1V+AOoyR53SIzwfZR5jY+FsLqr2o0mPk6GbzwS5Pk5\n" +
                "XBrbegxQ/UrfP4YNAgMBAAGjgZgwgZUwHwYDVR0jBBgwFoAUsaoX8OPPzNKniaaD\n" +
                "B93/btoH40kwHQYDVR0OBBYEFEWSz28Tk7VuNoLpo6HEQTpxsHIgMA4GA1UdDwEB\n" +
                "/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwKgYDVR0RBCMwIYIfdGVz\n" +
                "dHNlcnZlci50ZXN0Y2VydGlmaWNhdGVzLmdvdjANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
                "pgUgjEi8b3mM4voUe2Wt14cuFOS0YImUvk/Pr53xJiZPLyJkBOVK821wqBKjmmD3\n" +
                "29NaX9nshLc54lZfqvQBHTEWWBPeO1um94vimYyRNMVxoIuEA8c+a3RGGQndisFP\n" +
                "2098JFQjdz55pW4NgG26CJNutjMmCW17GmVTEJCiQEpVrRYS0QEaYUZya1yp2Thr\n" +
                "mQJGt3FyMi+LuoKqlhJsq1892cb10GO0E0Yhy/X33ihpbCXFMs7e5kqYa4oHRJIi\n" +
                "cScs+CqFDO98FpiQaccUpWlgIbHIq/R2t6GcXgSsK9+JLrJqn2TMMpS5O2Qmy/bl\n" +
                "AHzuGjGn+nomfAVFRuEZgw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDNS1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid DNS nameConstraints Test31" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID0TCCArmgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROUzEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBqMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE6MDgGA1UEAxMxSW52YWxpZCBETlMgbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3QzMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMWz\n" +
                "PkxcjfrTx5HDvt3XZVNg70GescrEk15PleNAp9F5sKxnbKvlJXk9Ei6imacf6tqY\n" +
                "GH4gtc0fdD/Tk77oT26I+Q6E/hPk+QvoFi5CyHEKa1EsupAWS+/yudrVkKCxQgoi\n" +
                "43pTUFPVZf2OgnTyGAqR+n4EjOeFKCQbXblGQjOQm0gHXiSDqYgsAam1Hw3P/R33\n" +
                "6SNSrs1ClBL6m2cLE36e5zANzNfl9ev0avuc2QS46XNteE+Dol6d6B0StjCV2CSi\n" +
                "Ipl0tqvurU/fYPJsYFVVPt2cdHEmig35BY3R+A+LLyYtT8j565p0tsoFtpTxC07e\n" +
                "FaV7CAwwF6qtUj0TpPkCAwEAAaOBmzCBmDAfBgNVHSMEGDAWgBSxqhfw48/M0qeJ\n" +
                "poMH3f9u2gfjSTAdBgNVHQ4EFgQUcth3X+ns0hx1Nih4TvYCKoI/bXMwDgYDVR0P\n" +
                "AQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAtBgNVHREEJjAkgiJ0\n" +
                "ZXN0c2VydmVyLmludmFsaWRjZXJ0aWZpY2F0ZXMuZ292MA0GCSqGSIb3DQEBCwUA\n" +
                "A4IBAQA6HLry6wY654Uab5ADefymDgTAUI+zFlTB4rxL+zz5H01iwjyFOQDhkpWO\n" +
                "yJLbj7Ncwr1AZW19zYAeJ9et3mWTv6assHW22CRecv1M/oSFGmNlbTUYS/UPO4wc\n" +
                "rCOx4rAnTXwIPaUdzF88HVdGqlTr45sUuH9OwQDnPmb+TKLCkLfRo+TUsvBhzjeF\n" +
                "+tuaca3sFhLvw8hZixlySkpYRmQ2Ih+w16G2ocA3tfqSb4U+vhM4PAqeRP/E1i5K\n" +
                "1WRY5ZTuSn2nMS3s+ItayivhPoWjMBa3+LIqvlZM1vB6ALREKt9ab5B0lj9IO3Jf\n" +
                "SHQ4skVRdnOis7u2cSrdZnbCy3Xx\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDNS1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid DNS nameConstraints Test32" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDzDCCArSgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROUzIgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBoMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE4MDYGA1UEAxMvVmFsaWQgRE5TIG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZp\n" +
                "Y2F0ZSBUZXN0MzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDjO31Q\n" +
                "u1gnI8gYuBTTqe7O7qzK1fRNCHmFrxovthEckh/m2yz+SwSMCRV3tYWgOu4g/f68\n" +
                "Gr0+3+0fhwI8ZNlkjvjZG6ZaaDLQejsfSwRDdB8OcB1V6p2EMSxRBGj6ZyTGObq2\n" +
                "1XCUJhWE7aT4UDw0gZ9Gw5MsdzP9Mm0ZujF+nknrMx5IcktNwz4GrZ+PXDEd/7BU\n" +
                "ZoosEtzX33b0toggo9LPTKRlu0c5GJqLbb7dCj9nuErxTaR2x9xGFdYdSuJxhlPK\n" +
                "NwGCPV/RdbA+b5LmhxfBoCNRYsDHc9SGaxJxuzxJaRke7uqNc8E8xiEBb36uwN6B\n" +
                "+P7SaqaFMB02px9XAgMBAAGjgZgwgZUwHwYDVR0jBBgwFoAURkicQgmOXVNw2BYe\n" +
                "4MHJGBU1CgYwHQYDVR0OBBYEFC+f+0RS6fd7DHdf1A7xDiGx5OcdMA4GA1UdDwEB\n" +
                "/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwKgYDVR0RBCMwIYIfdGVz\n" +
                "dHNlcnZlci50ZXN0Y2VydGlmaWNhdGVzLmdvdjANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
                "Afn8pFtzg5Eyk7U4Qz9iaw0+eaMiO4wX5iy8CP32AzJf7EJrykGk2G+/ZCJirXdB\n" +
                "KJHPHqVa1SuIg/I5OOyku3VAl2nsVvR3FbouEDwrRQMMF9AaRAPHW0Gz6sb3DZWO\n" +
                "gtoAdJgPQukkQ2t1Usl6DdsObESMNM+lE/O3qZBPvAS5FNuk8/GNt/l+7XUYub5M\n" +
                "q9myI8bAITKwYNH45K/6uahjVM2Hzzw0cx1DINxfg9PxP4wmA6AbZkgLazgwGaZa\n" +
                "Tv0xkbdy7RaP0nDXXRTlKpPYvplmmsfiYQiB1J9RedeHXsoShC2RPPcEWe9kAjcd\n" +
                "ZVx3nY9LshmNiUS5XqpLhg==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDNS2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid DNS nameConstraints Test33" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDxjCCAq6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROUzIgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBqMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE6MDgGA1UEAxMxSW52YWxpZCBETlMgbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3QzMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMYb\n" +
                "B1v9GpRI/WrpcpiPQwAnQbViU0MATTXN5t8MypI72+0ExFrnmC3gPpZkImwXOlIn\n" +
                "EpFA/EU2xNrc5+1mzC+rfPUzZ9W1xpM189Nsdobp7UP8laTGpeP1qB/5bYKwHr3w\n" +
                "poPYnm189HfyTcVfOBqrb4w8SxyfZBZv9znzHlNayguKAgx+7v1IBrPSYz2dQKpm\n" +
                "44UfeKpdRLfBYmfwtFn8fo7G+gSzLev19SdPiiTM6Mm/7c3wvSjPfoFChOmCDjmR\n" +
                "hHcDC/Y3IOp9913OU6MyfX1JWWtCekDmovPzH9FdYvmYA4qJEP+RTHLG3Tjjx1MY\n" +
                "rGfjZf+FnQktoa7DG1kCAwEAAaOBkDCBjTAfBgNVHSMEGDAWgBRGSJxCCY5dU3DY\n" +
                "Fh7gwckYFTUKBjAdBgNVHQ4EFgQUqPuoi5cYHAfhxk4Sb8kAu3oLs1MwDgYDVR0P\n" +
                "AQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAiBgNVHREEGzAZghdp\n" +
                "bnZhbGlkY2VydGlmaWNhdGVzLmdvdjANBgkqhkiG9w0BAQsFAAOCAQEAL59qoRdK\n" +
                "H5WO0ZnkKiOAfs0egI4Hm9xbC+xax2LVNHxtmsXa1ksxOgX9dMuJH4uo6XXzNqyp\n" +
                "KbZ3m6z6g1lAsdfww1o7d+7EOIGhTNOBWhRZOxYe+XEWxzIKKgO7qPGffYbEhpM4\n" +
                "HI+2QsGnKGP2iBcVWS22KE3O/3xRGjiSUff9hGsroTtv8xTbPBA93d4Vr36VzRp6\n" +
                "noAywsV0iZt45Zpoo368aX+Ph62TqXCg/1+VERrG8OJe3+lWQqeBfKo05pwZhh7D\n" +
                "Vi1VnGCLRptvUiwJuiOBksuCI6Uidi9vEN2DaIz5K+8mGAWn9C9Qjps/Kat9dHFD\n" +
                "ctZ9Gd4lR1XzyA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDNS2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid URI nameConstraints Test34" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID3jCCAsagAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIFVSSTEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBoMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE4MDYGA1UEAxMvVmFsaWQgVVJJIG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZp\n" +
                "Y2F0ZSBUZXN0MzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDO5F/3\n" +
                "wWBzxesA5Y/T/BL4plearIiSXCj2/J6WAYteqn0mrUwJ1r2apfS0ZjNREqqiKj1c\n" +
                "nPIi2mIfqanPTTIYJTfvnR4fAYYpgU+b8jGCmF1qU/G7gRuvhfAV67/NqzkvmiRl\n" +
                "Nq2qWN0xS+r24fotIAtBhh/kkzmRlgK9rJceRDX0gatRtUkZwNCDA8f132Ghsznb\n" +
                "REzEzxlWWp1sTi6g9PgL/rvGH2h1RrhUby291O0fUQ0uplSXPgodYZxkS52o66pZ\n" +
                "3pBTdqvCc7evLZfRaxz1uuFl2IYrYXUos0iOMoTqPzo5jX29Z6A4N78G6tB0Uksq\n" +
                "nzGTPg6iPwrHxVNvAgMBAAGjgaowgacwHwYDVR0jBBgwFoAU+iitQRbeKmgXyA8c\n" +
                "Iz8mA94CFAIwHQYDVR0OBBYEFNZ67DHSA5qsuP96390yL1+UdqlGMA4GA1UdDwEB\n" +
                "/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwPAYDVR0RBDUwM4YxaHR0\n" +
                "cDovL3Rlc3RzZXJ2ZXIudGVzdGNlcnRpZmljYXRlcy5nb3YvaW5kZXguaHRtbDAN\n" +
                "BgkqhkiG9w0BAQsFAAOCAQEAUAfALBN64JUbbsGzkZBy5SAIDD8HJCpcxlMgJ6UU\n" +
                "4RkR59QygGzwquDniZQvhDJ+ZqzgkBFY/k/UFXdpPJD6baREO1H+wTz/TPhtxMv0\n" +
                "5n5Ycbno9qhlIr4JFj5gTU0DcDcYke7AztSOxyT3D7/Y0cpUOipTay0BmZA9ndB9\n" +
                "yGnIIALUzQ5pDttKZso5TX4Tf8c3Y8V5VqhiN/dOQnXnsanyBSsRhn6jaPTowi9s\n" +
                "SjNXIw3GgiWod26Ld9eRLMljkNgA1h2nIwkqIfStvJMzWVEd/tPUj5+lF3L2EqL8\n" +
                "8E9ziMi7XGb1hpCr9oBN+9TaDQF58lRFiwZO4c92bCqmJg==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsURI1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid URI nameConstraints Test35" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID1zCCAr+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIFVSSTEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBqMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE6MDgGA1UEAxMxSW52YWxpZCBVUkkgbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3QzNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALA8\n" +
                "CtHPii7fw28cFZaZuH3dG0rXPq84FZPv6pvNJw69Z2qgNbiwyudr+U3JacGVOQl0\n" +
                "DxncAg+RfSCSzkZoIwtukH9TC+IFD3J4POTu1uLATudMVsiDM0gmzHR64zc9GRSQ\n" +
                "2pfSDs5zHFStkdfcZau0xxSff0vXU59UtO+n6AuVOZcZfosrFWTxSf2hEyyt04MH\n" +
                "FVH/vDIT0mym1kChxQ+NYLqo7A104ZTrJq4ejxFP7Fp62JGqvDGLSnisFNjkcVac\n" +
                "5f1dehlAIm/ssRyMHK+Q6Dh2KrjPRdkcSuYzDFz82ZhWGaoBj3OrYYljISCZnT8p\n" +
                "s0HqA6BFbBXhveCFVgMCAwEAAaOBoTCBnjAfBgNVHSMEGDAWgBT6KK1BFt4qaBfI\n" +
                "DxwjPyYD3gIUAjAdBgNVHQ4EFgQUokLglRky7eXtrwkCdqZ9KB4g5tMwDgYDVR0P\n" +
                "AQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAzBgNVHREELDAqhiho\n" +
                "dHRwOi8vdGVzdGNlcnRpZmljYXRlcy5nb3YvaW52YWxpZC5odG1sMA0GCSqGSIb3\n" +
                "DQEBCwUAA4IBAQBY+uta9QOhKurTMvpDULkPL4HU4wWHAN7+kL+Q9va6SDimwLTt\n" +
                "N+PT5OfoPbALrC3ETTdcfyJXcvvEbuLcu2/mozR8ZPE76pLeV03v73UlApv3pfzM\n" +
                "u0ydogvBtA+//I2cZv9JDN55LwM2NxHzEps0GBNjDSqgF5jEPqOqJYZF3U5JvIvd\n" +
                "tx6OzIGAbq4Y1p4iiyMjEhOZUZ11V9V37LPl7wkWxbp7a6a2+jZCupfWJbDLJHiR\n" +
                "MrEM7imDoSbkOkwgajrtmRHksuQi1fk/faJfP84fVRFIrBzHhPgG8yV5fLSmLgTp\n" +
                "O7lmeu5uvo7psQ2Qa1JHtMbw+9YqgK23nR2I\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsURI1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Valid URI nameConstraints Test36" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID4TCCAsmgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIFVSSTIgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBoMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE4MDYGA1UEAxMvVmFsaWQgVVJJIG5hbWVDb25zdHJhaW50cyBFRSBDZXJ0aWZp\n" +
                "Y2F0ZSBUZXN0MzYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMbB0+\n" +
                "65ySk6fi6dtExfV1zX4fF6wQUg0um9bpkU7sssBLoEI3fNMzQTM1iwjpbQqILiRP\n" +
                "0zqi/pEy8LTZZN0H3/Bvign4sGWhf45iMB5gIVR788WqOKz+vnTHjzjve8a3y2BG\n" +
                "0obtbCGD03k3a1zu3EH6X6ZXQHN5AXFgwQgOkwWf0azdHUb7JO4fSFMH2hNEgOJx\n" +
                "2ip+HuWZfzUzIa+as9ysh7OCjJYySAp6jxzvrQAsRcUQPd0XLuJKUM/tWXAzfqgy\n" +
                "Rk5RsfcnLiBw/Z4fB1UzhN5RSGyBxqwiibLl5zeEQxDETmW7kVDN0V0khIpX7mD3\n" +
                "frmvHfx1nzaSU4IdAgMBAAGjga0wgaowHwYDVR0jBBgwFoAUTeuJcd/wBAGy+nY6\n" +
                "WLG6YN2M08MwHQYDVR0OBBYEFF3cy5MzmrQiP79DwPPCIj7VxjfFMA4GA1UdDwEB\n" +
                "/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwPwYDVR0RBDgwNoY0aHR0\n" +
                "cDovL3Rlc3RzZXJ2ZXIuaW52YWxpZGNlcnRpZmljYXRlcy5nb3YvaW5kZXguaHRt\n" +
                "bDANBgkqhkiG9w0BAQsFAAOCAQEAXHV9C9XnmJqFiGQvsQv+Mtb3wU/lbRlv7P4+\n" +
                "dVItASgqIPJwjrGAEkFjykCDUd/ozD4lIo+UxKwXAEmH53wyXLnnupluCnPYarTM\n" +
                "KgWfQlBj/eO6GNEQLujg05EK7VxfFnr1jPXEaVBIacwwXNlEGVFK/j5GaOKh9kbT\n" +
                "SwdMgzGI8R+k8mYoLbVcE3Q3v3zsZPjsME8OBW3d+AytEb2gWScJv/iDfCSgk3rQ\n" +
                "F7NENzPMDreitDNAhxvmQL0/KGewkCStOjFHaBLQKR+ELq8TruIEuypNl8BNFQf/\n" +
                "HSf5MCFAlkXUNaff+m/vEvm6j6l4WlcuY3cYA0BLG+OTnSnTCA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsURI2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is NameConstraintsValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid URI nameConstraints Test37" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIID1zCCAr+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIFVSSTIgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBqMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE6MDgGA1UEAxMxSW52YWxpZCBVUkkgbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3QzNzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM2x\n" +
                "nbrTtgYrZ7vvgjKR+rj+GcPuu7hubTLNz64dJYq4bO1F2Pp3AGeit4SFt5mWT67B\n" +
                "p+jjMo8dpqoO7+Y6+sebnJv1pharZ0fzQodcfl9/wTPTCwQ3hd5hOIwIKEC5rwhF\n" +
                "OfC7CfAG0LBIc3L8ayYbDu3rfvHr43tSrXeNQCDs4sT50yYrkmSc9cSx9zrBin7y\n" +
                "1XEEsyvcxbwG6vfazFyBtWylBIxrryPqp8/tCpj4v+YKpjNtBXbtI/rh3NQRWqmC\n" +
                "0/byyDKuu+ZqkOwBZ/VWX0QysdoH+z010rhboJp09kQqL9P9hgB8WW+8zBk1mjnK\n" +
                "fhk9TBzniVk7SZFntLUCAwEAAaOBoTCBnjAfBgNVHSMEGDAWgBRN64lx3/AEAbL6\n" +
                "djpYsbpg3YzTwzAdBgNVHQ4EFgQUtJ9QNnzYVFt58I4Udp2pJfKkuSAwDgYDVR0P\n" +
                "AQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAzBgNVHREELDAqhihm\n" +
                "dHA6Ly9pbnZhbGlkY2VydGlmaWNhdGVzLmdvdjoyMS90ZXN0MzcvMA0GCSqGSIb3\n" +
                "DQEBCwUAA4IBAQBB9r2UKkXqMVYrheLH937+0QmR/JOtK+oaJcw+mJBOzy2NbIPO\n" +
                "7m9OEAElkt/PSaONwtLyuoEm3/c2Z9DVyFE/ep1ndQ/58Ow9vj0WE2mwU1zhwn1x\n" +
                "R/pZz2WAfFQrgJZLqFoACN38Hsb4SsGbDIWGQrJSabtJPr2XDfKE6TBhVAMHYtcs\n" +
                "Xia5zyRiL8c4BEATlHrBlw1CngLBfBIDGDc9sKaXboOoz44uyisAwG6FJ9XR/v47\n" +
                "Wt1hVvxa2WF7AJAI+HZn8KdlLyJK9zi+eCETErxPu0hwMLhe53M+MllHSzD9kOfq\n" +
                "7gHu2jUzx/W4G4YH5jEo0EW8qEUcCEQX1cR9\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsURI2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }

    "Invalid DNS nameConstraints Test38" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDxTCCAq2gAwIBAgIBAzANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXbmFtZUNv\n" +
                "bnN0cmFpbnRzIEROUzEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBqMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE6MDgGA1UEAxMxSW52YWxpZCBETlMgbmFtZUNvbnN0cmFpbnRzIEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3QzODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKh6\n" +
                "dMeji/U5K/ekBPo8CedDexJtu59S60Zbb3AdsoCF+t7mMkB7bkSY9aNOPXfsmBfi\n" +
                "YH7FJFNzIwIoG0yHAB8qROxhbt4STVpB4c3XyqkWByLdHAzPM/+CAwX2ZtYTLF81\n" +
                "FqT8KM7QmUMbjkcNx87nD+r8OQ795j0fAQQ3fC8XXgYVdDdfuoACAyYVgJplwLMF\n" +
                "ejdjj72LERuDgiJKHy5BiUrtOr74ZRRoysDnX6C9cAD6BJjkrvFryQmCsnifit41\n" +
                "3X5TWR3nSYY+93/ioiZ8kr+xDCtx6ODFs8DohTpue+SNnTW8w7QwtoR4gxnLWw2C\n" +
                "3FNRWu1l++/VOOZEd0UCAwEAAaOBjzCBjDAfBgNVHSMEGDAWgBSxqhfw48/M0qeJ\n" +
                "poMH3f9u2gfjSTAdBgNVHQ4EFgQUzkAnIqjWGiY7B5H+8RntUEbOS3cwDgYDVR0P\n" +
                "AQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAhBgNVHREEGjAYghZt\n" +
                "eXRlc3RjZXJ0aWZpY2F0ZXMuZ292MA0GCSqGSIb3DQEBCwUAA4IBAQBFZ1PNe87h\n" +
                "xxEKYU1zDBenTJ4doWDxfNls/SC1fl9y4sV5gYdVvXMfMvFNpv3cuO9RdFhc/r7U\n" +
                "an8zS8YA1bP+ts5EDma3yIuRkOAifEeE1ivPjzmEH0acOsfFmjgF5OBqS850KFqS\n" +
                "Gtxa5YDgeuV6/GaUh+QTnkweGcQau51QIalB34UMxmG93hsNI3M4ZxPAiInJjb5n\n" +
                "+XKyQBWwAhaPhGPVbLIU0BtnyafxIs3fkksxFvp0TvrxNoDKmyGn1xMPf66rKgPV\n" +
                "ziiayHvu9e8uhwEjXmugCy0T5zxb67CVVgHofZZfphlk99gUzeqr0rxA+7gPsoVt\n" +
                "99WV0A+bbNk7\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(nameConstraintsDNS1CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is NameConstraintsValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "NameConstraints violation at cert index 2"
    }
}