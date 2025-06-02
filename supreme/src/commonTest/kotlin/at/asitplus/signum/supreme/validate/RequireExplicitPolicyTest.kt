package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificatePolicyException
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

/*
* PKITS 4.9 Require Explicit Policy
* */
open class RequireExplicitPolicyTest : FreeSpec ({

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
    val defaultContext = CertificateValidationContext(trustAnchors = setOf(trustAnchorRoot))

    val requireExplicitPolicy2CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDoTCCAomgAwIBAgIBLzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUjELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIjAgBgNVBAMT\n" +
            "GXJlcXVpcmVFeHBsaWNpdFBvbGljeTIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
            "DwAwggEKAoIBAQCzxfi584eF82tOhWkMbV/3OVpGrWH1czuMyaq0z0aPeRgBRrIB\n" +
            "EIvQpq+7Bn9NttfyrXjsyJOt47rtyV0yBGkEyBt/UmCehaLuEROLemMB4uzcKLLS\n" +
            "fo/dcHd8MZV4MUn6ESPWny0PJADb4akSbhWS6H5LA9j6qeMc211nfgy5LBjJiqNL\n" +
            "6pEdyFfiW59UjL3E180/pm5ktxiUbQAjqs39vr5TEUrcnXIGEwD1wNyia7HovdoL\n" +
            "2dvSb7CbOw26Gv5EKLPKfBTBGM79JUnMFG7kWXLUAhGbosCI0bLsZO4ox7q0hy3M\n" +
            "NMOkxv/4yOqu4g4lg4ldmfxj5xSV4QooFSrzAgMBAAGjgY4wgYswHwYDVR0jBBgw\n" +
            "FoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFDap2fuqOC+g90w72YWd\n" +
            "mhWjLanHMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEw\n" +
            "DwYDVR0TAQH/BAUwAwEB/zAPBgNVHSQBAf8EBTADgAECMA0GCSqGSIb3DQEBCwUA\n" +
            "A4IBAQAe0P0wi2luJkXyOChUK4ruG45cD6IIep+GwGXYtnsq2fAXIWe1c8XCQTyi\n" +
            "1TrQBK+AiM/AREdH2ZVSA+V44zgmPIXIiVa1teBPXbuvM7GQzOaUU5Dv8SMCjRzH\n" +
            "ThsV5bkvTw5V29Pk8vbIFNMzSFeWfoatv4RB0a5ahW153q4CgDOUyJoMOcRGRi9L\n" +
            "xDToUwTICmz4eNcMA04n0U94wnqZiNhcLEdfyX95ZspOAs3E2YGBr/Wi0slN9+6Y\n" +
            "CpdaYY6UzK9azt1q4t9p4PTfbYDxi6hPksgMEoFfUtskikrdD5dPYcG42IzCTOks\n" +
            "Jx1qxicm25mJ7TuNhtQKBeQ3FeXT\n" +
            "-----END CERTIFICATE-----"

    val requireExplicitPolicy2SelfIssuedCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDmzCCAoOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcmVxdWly\n" +
            "ZUV4cGxpY2l0UG9saWN5MiBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
            "MDBaMFIxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
            "MDExMSIwIAYDVQQDExlyZXF1aXJlRXhwbGljaXRQb2xpY3kyIENBMIIBIjANBgkq\n" +
            "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5ByQjiOjxE+oZnilZmG+qagOo289Fp+X\n" +
            "R9raC3r0WvOV/DiAIO2m+PMkq71mXXR3jc/gIL8QqIzS75W0XToccyVOnY6uQSlN\n" +
            "avFElfBmhxMnYNC/kcP/cpne4iABELM3csuIRUz06nFXTsSkQSHa9sfc3jin75dB\n" +
            "5JFHF+WzVBbZLa0mUMweVJ0g6ukWYoyEqrRSME19jw3X+VKkQxqOBR4BEiKLLVHZ\n" +
            "0DWzomRmvC/YOa6QxlHGlXO6myPBCVt6xqpzBNsBLhjKb9aTsxgRir8Wyo46FGpi\n" +
            "OBGfB8ebefFEQuwx/Y3TLZEUyaAvd7MO85ftuvp8weAVUIw0Ks+d2wIDAQABo3ww\n" +
            "ejAfBgNVHSMEGDAWgBQ2qdn7qjgvoPdMO9mFnZoVoy2pxzAdBgNVHQ4EFgQU76va\n" +
            "2OGAMadDFu7Edg2v7G3yYKEwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYK\n" +
            "YIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAM\n" +
            "H2gKVmtNkx9bL0dvtkEPs+89dAzNW36hrK3NTIIDfe1JjA/u5W2mMHORYJIDgvWS\n" +
            "viva+NsPYDNsLiF/okUX/B+d+zUYBweRDG2t1QQzQGuwArb/y07eKTm2VZfHuvR8\n" +
            "UJhP/BeqW8ftZ4NU2P1nGwvTRaENGvih7aPxJWZAyqlcQrE0Je0iFM8V3tJfC9DH\n" +
            "9xRDUTADrgsaWMajbEea+cFAhcY7E4YuZM94DKEvXIVjIMM5ifOGm9ySnf5LAsVd\n" +
            "3ER6jg90zfW1wjqC68nPWpHOfglWoJ7QzCxp6IqGkVE3tFoVIJKz8d34bKBoyh9R\n" +
            "xPdQHkHs3XLydaxFC8kf\n" +
            "-----END CERTIFICATE-----"

    val requireExplicitPolicy2subCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDnjCCAoagAwIBAgIBAzANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcmVxdWly\n" +
            "ZUV4cGxpY2l0UG9saWN5MiBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
            "MDBaMFUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
            "MDExMSUwIwYDVQQDExxyZXF1aXJlRXhwbGljaXRQb2xpY3kyIHN1YkNBMIIBIjAN\n" +
            "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsi+sFt/pVAsHLB0tfOfQJAKTDdVo\n" +
            "krxRAE9Ykhw2mJympAhm/yEB/Yokq/oDim+KjRlJ9LQpem0qOjCTM+ApZ4ClsvcC\n" +
            "apqvHDKpU2kBXlLyAFPRz0WaKGUlvNUheBkiQOJEUMulXF4VtsNFZloCc5fTKLOK\n" +
            "62UIdnPMWPEsU0/T6Wp03yT4mKF4mV7cxcBRDwYOhb73wCwP9sE/5DshU4uaX0vr\n" +
            "Zv7MKr5DLkq+TxCDrOGi4nRdplw1TOog46OIc7XuE2nd/Oez4tgbE44tACRfvdZz\n" +
            "oQToxX6mw09d50dlIy7Sg+5U8U1M3T74tQ91LPH9WUQ3qfR/0BGVXMOAXQIDAQAB\n" +
            "o3wwejAfBgNVHSMEGDAWgBTvq9rY4YAxp0MW7sR2Da/sbfJgoTAdBgNVHQ4EFgQU\n" +
            "IHf+TDCN4rNRHY+w9xx/HYOYDkcwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4w\n" +
            "DAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IB\n" +
            "AQCqda8jpBRM00PZxYoWbSe1nLb62jNqZ1D2b/wMEKgBqueQhV/AsqCsqSKoGpKy\n" +
            "9J1ZYcUfRH941kdMAf9zRq/jtuECva0ZkblFq33mx3a+5/7PNesOU9YglAtEL0lJ\n" +
            "mXtpzaO3tPO4gyODSU2eWdjBgbmndDugp/m/t51SdcR8fhiRkaLIERnybXt4S/FH\n" +
            "7CdzrJjoLGmVZzigQa1de/6MIyumAXxJfxPmlqxomS+uDzGys+CGMVJf/hJnZJ4m\n" +
            "QH1THJUNfJFyx2VvNqQqj6bllO79tcWwAIwizPr46qO7ZmwRAVs2HhQgEQn9uIti\n" +
            "fR/NRcbd6E2c2L+TYxNYfZ9r\n" +
            "-----END CERTIFICATE-----"

    "Valid RequireExplicitPolicy Test1" {
        val requireExplicitPolicy10CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDojCCAoqgAwIBAgIBKjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIzAhBgNVBAMT\n" +
                "GnJlcXVpcmVFeHBsaWNpdFBvbGljeTEwIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
                "AQ8AMIIBCgKCAQEA89pNhXn+jUxGpeJ1/h+iAlDoB5GdV8Do9wWsj8xwV6wx8QAi\n" +
                "7MLPxjS9/zzCmmdvv9sa/tPZFYObbUaY8VDtQoksQKtW57OZgyAJTbUj1vV6VPDB\n" +
                "U55xFOWaI/pesiO1+q1Xzxs5mZKVqChXQMIxzEYbN1opf+48tvsK4cOPLx/QQuEL\n" +
                "E0q8nnoL8ePohm+8rTEtsWevzHz+PEywncSG+xu3SXC62gBm0Ij6v4178/CyTOho\n" +
                "m2wXU7KAowokvvRx8ZqI2WS9Arir278fHzCsdjYeBCnybJyES+ldKZ5tvANLh8am\n" +
                "C8loUhtoBW/HvAWFzOyEgucWqMmH0dUSiDLe1QIDAQABo4GOMIGLMB8GA1UdIwQY\n" +
                "MBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBQZ80wE0V/VgEfz+DQs\n" +
                "EYHkmM9rnzAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATAB\n" +
                "MA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0kAQH/BAUwA4ABCjANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAi0krrdtrtcdh6y64lMi0WeCP4QILh7uXhceEtxyafJAKi0D/t2vQ55oN\n" +
                "rAP+ZnIT0jOBBOE0cE6kyIcSa82rvNvjLR6fPqEhyXtE2i5dZbJBw847jP91UyBZ\n" +
                "4QaA4jzJh/cz41U0GRv1dPf0SF/9WcsWKZnqumbZZ/NG7Zu1QJrF1+GU17rOWFUy\n" +
                "CndBlxka3QVJSTzLxhXwbw52YiXvLJQm7mwF9OTuDU2ffZ5WKuOSA7rXumKNUAqD\n" +
                "d/U6lvBwChFlr8sAqbXHcxh4ZqboOaTDxvBQ9rLrjKtcuA9N7udGFjZr/nEwqH+t\n" +
                "vJgmuFX0Tkh9gH9AZax/zOWZivL0nQ==\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy10subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDoDCCAoigAwIBAgIBATANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMacmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MTAgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBWMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTEmMCQGA1UEAxMdcmVxdWlyZUV4cGxpY2l0UG9saWN5MTAgc3ViQ0EwggEi\n" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVX0CKln4yztxPjF30FSL1KXKy\n" +
                "G+0mCyGvYaITtuY6wIxSEY5/gx5llypjWstkFJK6Y5K+2aeHzPzcrsxd2jg3mG54\n" +
                "WOEpdDgnOyx9CPA8BjWVmZxcnzLzikSF66IoniwImkpBSpK+vzouO/aiC2kEDvLH\n" +
                "5ywmwtHhW5fYUT8maw7pzJEbE1ZcQivDNxrXL0feO6neRGhNds53tC8WDFSgtZNK\n" +
                "kNsPT+S6FLMzs0dfLFbg21WHjJ9MaG2kjH1yuKI0KmXJ+RbM3/vngJPmIzILx8pL\n" +
                "+o4mRCSmIYDW24WREsYahWvismJ+Yn+xYxUSjYrAqw8XTTWFy+pBDJooCFYpAgMB\n" +
                "AAGjfDB6MB8GA1UdIwQYMBaAFBnzTATRX9WAR/P4NCwRgeSYz2ufMB0GA1UdDgQW\n" +
                "BBRuGKZhJA9o2y4GEZYmN6/JeClWBjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAw\n" +
                "DjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD\n" +
                "ggEBAOkcAeSy758gjhUGHr83+uAMg7509xvYFSmyTvic9b4TEjUTddYplwZ4zHK+\n" +
                "jRSLsOzh83ZD76uVcGn12a3FbFj7GmYC3o3409ciWWefaSZ0zxFsNmvHB4Y3kt8e\n" +
                "Emjzkck/LLNri5SGKVlPdYEBWQiCvxdK/jN6YAWpbIASPSbNNiSDUYLXNFWhaRVs\n" +
                "8+RgaEHwyYW71IHOZ+qWhnjmtYQUL6uglCLcIGmMzkxXIgUo70utC5DbTtUYVDZ6\n" +
                "glLca7VUQnES1G0oA85/nokRVd1TxbKOeBJoyxRf5IjRbW6OIgLxUYjFmxF5MB0p\n" +
                "7LHjIkT/5vZy/lERobzh44QI0/s=\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy10subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpjCCAo6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEmMCQGA1UEAxMdcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MTAgc3ViQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMx\n" +
                "MDgzMDAwWjBZMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0\n" +
                "ZXMgMjAxMTEpMCcGA1UEAxMgcmVxdWlyZUV4cGxpY2l0UG9saWN5MTAgc3Vic3Vi\n" +
                "Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3Q6OlKYYO7GHk++9w\n" +
                "xG8Uaa1vROnO94XkBCXxGvbcoEk9vLTPMrU5LDNeb2b5jsqFUnyr2VspNrqVjsft\n" +
                "SWn35sbByY9KvOvxtVe9CKKbQsnr/xdn8eAbWz160y1yzfTgKgug36awApr+Br3v\n" +
                "LKAr4+pRyFoFA/rOODTgCvAAw7kWqSo1u41x3tr2trxhX5LysQQu4ZAmuUgK0FW/\n" +
                "GVElVC3XqkJEj7f87CAJ1UJvJbkmX3fwg2ZLbH2v4UihwVj1rwOmRUz5mrxVM6Qv\n" +
                "CkcBmP+gxXStOpWpb+xJbrB8ja6XEZ9E1mZvn7z0tVd/MMp2j/FvPAvIX5eK0jE/\n" +
                "rVixAgMBAAGjfDB6MB8GA1UdIwQYMBaAFG4YpmEkD2jbLgYRliY3r8l4KVYGMB0G\n" +
                "A1UdDgQWBBRYUE8O8v5yJKTQdz+glix3tSToITAOBgNVHQ8BAf8EBAMCAQYwFwYD\n" +
                "VR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN\n" +
                "AQELBQADggEBAM5UH8wRhIjUneCRQvs9o+G2dyjZ2vTOe2Fh7KyY48tnVB0WBn+l\n" +
                "Z+oSat2PcoEqGLeHb0xeiOdTStG+CIMBsKtEURm+6wm/O9McFDyu/zWAENdgqZfY\n" +
                "wQa91xLPw/mZ+p73SGqrRpFiOcmStaIax7ip6yB9smU9eIWvqJnRvWN69UvhIhjy\n" +
                "xarGYM3vUNC4uuhoZuzerUoZ+X4S1l84a0erkbGmH3bLLG/6xtS9jyIrfTN0kkPu\n" +
                "631e1/HICHgVyGzFxhzKU2wDlkLtWqGk71ZqxJB/hZ0GS9BaFk2k5LS/Jc/r1vjo\n" +
                "UBK1VkO0Un06qiXfa0JDsXFrWiMtycqBFzE=\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy10subsubsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDrDCCApSgAwIBAgIBATANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEpMCcGA1UEAxMgcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MTAgc3Vic3ViQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAx\n" +
                "MjMxMDgzMDAwWjBcMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZp\n" +
                "Y2F0ZXMgMjAxMTEsMCoGA1UEAxMjcmVxdWlyZUV4cGxpY2l0UG9saWN5MTAgc3Vi\n" +
                "c3Vic3ViQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2DO8cedU6\n" +
                "MF/8P1YnCcHKe47mA/BD/ZjRJFTpgEelXmhIk/9qcx5i+jYsQFPOIWPo/V1WacZA\n" +
                "4Z3WIdP57sw21CZTPX1JfaoygAlcaueoi2UPH2LlvnHGpOGfZpqtI/6y1Kfs77Rc\n" +
                "bsIMkW8zRPXY2DOhRaYEOzf7ueXiNFx9SDLolxyZPEJiGeFX3+WrDXjZVH5wnCgV\n" +
                "6t3l+88ZsLQ0WRgbi1gocOBxOtrR50JkNHoOFwUNlqPibJvBkLYrlIOvJiPlqXXj\n" +
                "y5lgxMCyeSH79AJ9Q/UdMbJdC8HNmXgWxXuK+vInnaOJkjmQFY9MVMq35jIdSaZD\n" +
                "69D5hOWuBO0RAgMBAAGjfDB6MB8GA1UdIwQYMBaAFFhQTw7y/nIkpNB3P6CWLHe1\n" +
                "JOghMB0GA1UdDgQWBBSWjHH8Fag7ztnE+MPQX2lxfOgASzAOBgNVHQ8BAf8EBAMC\n" +
                "AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ\n" +
                "KoZIhvcNAQELBQADggEBACl0/KFW/P2mCzjLyGB/zUARmsAFdR0zvWjnKfdDAjg9\n" +
                "5Tf6At3kqcgTWt7qiKf58NK1S4BqcOQvYnYP3YeSmBEirMgtgJQ0FGR7R0FgoYhy\n" +
                "DY3tWak94nuM+tuucWqtQuyB6zGOh8Stc7uYkspb2tCCyQQ+pc/V2S6ggC0QuAE0\n" +
                "+yfuJEGlCyoR83ASr3aImoGcZdZ61aqK7bz0+DTDGJdbteBbSJ6WJsH6z8AFQ+yA\n" +
                "vmEXwQisnsufWYDtwuskwxoAGL+iTVYj1gtveU9O4zzh03hqOT6owGdjryX6VH9L\n" +
                "dJFtQ7bn8rR5fuuT9Oui1EgnwoKAtDEIpVQGvCEtLuU=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkjCCAnqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEsMCoGA1UEAxMjcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MTAgc3Vic3Vic3ViQ0EwHhcNMTAwMTAxMDgzMDAwWhcN\n" +
                "MzAxMjMxMDgzMDAwWjBpMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0\n" +
                "aWZpY2F0ZXMgMjAxMTE5MDcGA1UEAxMwVmFsaWQgcmVxdWlyZUV4cGxpY2l0UG9s\n" +
                "aWN5IEVFIENlcnRpZmljYXRlIFRlc3QxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEAsIqrLD1lrY+10wadJZYPQPQ2cChNLXuM+Aa4S1hCl3t3UlSsh5DF\n" +
                "8w5S0pJXjCYhsbzJu9jWxg6twBoHfan8aSE8/syGc0jyA3ySWxNszCvYzL00PGkb\n" +
                "+r76G/q7F9M9owZYrfu9tgjJWM2RG/9YvDH5ymvz2fcTgeP2mLr8fdqkZ2FyGLvT\n" +
                "GQFz2yu6P0+ZJ0PrL/jp6KPXAqMbAQUE8buAPVDliHyPN2gVQW74ox0IRLNnJZY6\n" +
                "o4YamrGp+RmadFyJoPGeTXrHHBo7VBl78m6bEeadNBBP8J6l3hYpEvREuu6/cbLA\n" +
                "hqKfCDwdhDzA/QzEhRNAGqiGBlRcvoM4oQIDAQABo1IwUDAfBgNVHSMEGDAWgBSW\n" +
                "jHH8Fag7ztnE+MPQX2lxfOgASzAdBgNVHQ4EFgQUjAmT8zwTrGYzjB1+ZnT6CY6n\n" +
                "OF0wDgYDVR0PAQH/BAQDAgTwMA0GCSqGSIb3DQEBCwUAA4IBAQBHABhR2hGz0n3X\n" +
                "3P5bDWSNmMpf4R9/4Rn38thteSd+mOukGv0Mw/cXccH1squBXYbBDqlHPobbhRWn\n" +
                "cfxVicf16NvVWj0vxEAfhDXpZ5Tfw+ufUCRs+ECjpZA1Gocc/uxz503iTzFFXSFM\n" +
                "CE7a7Qq8vDA+MnVJgdalnVegdmu6u4dQXtmNcX7sGi/FqrbGGVmolmuo6K7LCjF4\n" +
                "Fgk8IgR7G+Ks7Dd5hZg1ISu+whMonRCV4zhoSX+A4tc5UQqVlRbeJN80Xtzznl9G\n" +
                "XtuZuBvpeM/VSMucSwd2RRr4r803wVsYIGBTv9KoyyPy8oF6vqlxiJOe4Iwbxf9i\n" +
                "la8pgfuH\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(requireExplicitPolicy10CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(requireExplicitPolicy10subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy10subsubCACert).getOrThrow()
        val subSubSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy10subsubsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Valid RequireExplicitPolicy Test2" {
        val requireExplicitPolicy5CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDoTCCAomgAwIBAgIBKzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIjAgBgNVBAMT\n" +
                "GXJlcXVpcmVFeHBsaWNpdFBvbGljeTUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQDX64Yh0H261J0Gvd60y3m9dHEszgHONN7g8YYFETXH88aiScj9\n" +
                "G2p07n7WfwfAh0Mziuz0j0fibq4vSjAgGbxS9G3WY0+oxJAAIo4wfIAkP8BTG94A\n" +
                "qU1vFvGtl+Njol97tA3gxaaryyxwzzGIucLSCpH1pJwrVSuvh9FxxfCi8FMJ2P1E\n" +
                "cQHZoXTXuZQCzmY/uKODbDN2uDzokbG1eIitBuAx0936wxKzz6Yjd6IaVnR94AJR\n" +
                "gyL+QDk5Qly1I5blX99HL9svBtNRmUgeNZxMjnLfuXBkIKnSqrj9yJnKisQR0ci7\n" +
                "ZxDtbJ3FEXfuDo9vehdmevDyAmG/qWJ63MkFAgMBAAGjgY4wgYswHwYDVR0jBBgw\n" +
                "FoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFLuRg6uurt5c2ODykDxc\n" +
                "+p8u4TloMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEw\n" +
                "DwYDVR0TAQH/BAUwAwEB/zAPBgNVHSQBAf8EBTADgAEFMA0GCSqGSIb3DQEBCwUA\n" +
                "A4IBAQB4lgz3iN00AQ0XVL/Erti7xs7ENs/mzyiw3GLJgLVXpmVIgJe1hVSFNuEU\n" +
                "QV5WpTfTn+pxLW2ydjkj/mkbgyoVGpAMZlGYGgN2WzE2vcDBJVOlayZK95245k9p\n" +
                "ZZhdRhraZtaOS12+T3k+JVCxqGrKgLbVwl7Njs/WkXv01ApW0zzNi31sgnxHBNH4\n" +
                "i/uB0OYmf47PwuUAv3DJQbVZhetCgbZ5xZ0cSCqh6IKjvAJw//A3/r01kurrYVdP\n" +
                "aXRe6FAlZdZ+gWeWofmS1kL770TveBE34vKyFI6CIz2nC8gbEmisNmelNJz77/Tm\n" +
                "v33K8gJxQbwn+0htOdqICEIfMz7p\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy5subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnjCCAoagAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMFUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMSUwIwYDVQQDExxyZXF1aXJlRXhwbGljaXRQb2xpY3k1IHN1YkNBMIIBIjAN\n" +
                "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0yRFiPxcDa4VcjEIMjPxx2RaYWn2\n" +
                "HDOXqGxX6L5+pD8PLaXGLExhaTdwWNy+/yDaUUHij4pdFl/SQsmwtpEvfBD1vXis\n" +
                "2MZIsIGy4DWYqni8J6H2M7ofoafKyS4J5xkBh/Z9eBH85BmlPfJBSVVrR4zjlDQ1\n" +
                "B74tQTVWvznfpaZQomyr4Z4pzITkLANvEGvunIXckuIerkxjsjx0XzXt4W7h5aIt\n" +
                "b9Ow3W5wDh3qRwWgPgA9JkUQR+F5ZAZaqeZESGe72rTPir748IOqRKaoZPPh3IpH\n" +
                "IZLbh3hdAknoGNUg39s1EzAG6CR6S4rOFYqJIBmpnreR0AIm7XmziOwu7QIDAQAB\n" +
                "o3wwejAfBgNVHSMEGDAWgBS7kYOrrq7eXNjg8pA8XPqfLuE5aDAdBgNVHQ4EFgQU\n" +
                "N9O/3txQx6/IiuiSsMRIYfA6BAEwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4w\n" +
                "DAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IB\n" +
                "AQDGFqeMi0qNekHCj90wnNUgVkw3kwGyufgAbqV4VvFswdL8UwRZ+FAD32d4Hvqc\n" +
                "UYvrjN5TeoL3zW8p7czvq2bB8gDVgxxGT41v+OXd0uT+T34kArsJbi1nxA8GiZ9n\n" +
                "xU+XLWNp3up5wZB92F2I9J1W6psSxdPH4aBNrW/mgpckhimz5gWAOHIXiU2pB9R7\n" +
                "JsnRJ0VxcAtCXRWqeHqgcpeDl5cA0ImOVupvLOiF4o7JJ/+KfAlMD11Wvp8dcebi\n" +
                "S+1+mH9eod7daIN/fB39tMi+aTELILUvN8rmOz1COjN+lyVpZCbmSCo8wncNcT0B\n" +
                "NEdgddMknERZ9SRajlmnbyTv\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy5subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpDCCAoygAwIBAgIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTElMCMGA1UEAxMccmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NSBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEw\n" +
                "ODMwMDBaMFgxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRl\n" +
                "cyAyMDExMSgwJgYDVQQDEx9yZXF1aXJlRXhwbGljaXRQb2xpY3k1IHN1YnN1YkNB\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5osj0pPsQd7VtPH2r3xk\n" +
                "y+cCCrZpVCpWv79iVHsYL+FvNRoJcoAp4YRn5TVxL0tcaQ9GVUEG+mh8JPyr222D\n" +
                "PGnPiPKTNYyurrIouh70B1C6uCdQ5tYQiE9HS7WEvu9mPti4qVWcIurhfKHsvYAu\n" +
                "qzY+4UNrno9Qz9kjr4tYr+RXxHcby2TLXlvEKzgG79XmtvDW70tfiQhkQBEHSw04\n" +
                "j+dnUlhPRBtyYrXoAkDETKYK+CIso8/0PyDlZNqu8fJib6P1UVlCnsQ556r7cY4L\n" +
                "bjU4T49L36Y24wb6/5gKFBQxhvt9gsGUtNM6IUPtSh8MbiRXgHXmZFf/1niMiVXW\n" +
                "VQIDAQABo3wwejAfBgNVHSMEGDAWgBQ307/e3FDHr8iK6JKwxEhh8DoEATAdBgNV\n" +
                "HQ4EFgQU+IIvef+0fggC21uvMp3kNWG1bBswDgYDVR0PAQH/BAQDAgEGMBcGA1Ud\n" +
                "IAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB\n" +
                "CwUAA4IBAQA3toFMuFLrY/uxv2tTf2qtmCp5JJPfPdZYDmGVMEYlRJqX4IUSq4Ua\n" +
                "/YxDTGvdP74edOEmxgi4cDDY6Y1l0lgPT5qZ4J/uXhuVAull3UPnZYe+TIFf+VEA\n" +
                "ZKoC3JOf8A8+gFE+/0Fso7eLvI7C3YlL8BIQjWkfVylfXcf6wTk136XlMv9tKt23\n" +
                "lrVqqs3WHBu7jBHYw6+hUF8iv+1DRbLD3zVmrr3MJb2+Cm32DFvxujt6vAVuo0wP\n" +
                "bYUV3vF0QIGBgGbUmB4inAgmHYSiUmYzvkg7g8MF2pAthk20eK9lvLPo7PS468l2\n" +
                "kguCoyCmqySucoSul6rNQ/qiDhOu9ucf\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy5subsubsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqjCCApKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEoMCYGA1UEAxMfcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NSBzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEy\n" +
                "MzEwODMwMDBaMFsxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmlj\n" +
                "YXRlcyAyMDExMSswKQYDVQQDEyJyZXF1aXJlRXhwbGljaXRQb2xpY3k1IHN1YnN1\n" +
                "YnN1YkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlTf1ewQJZhIh\n" +
                "4PmJ+VD3TwcCt2e4mPpSH4n3WMFIhLPk4cLQr67l4TjzZChg5ok1rhb8RrOXjf6L\n" +
                "bL21MMx9nppk2WFfysWeYCz0qvuYH0UAUi2xze716rwNDotvndDSV9bykKjGOws4\n" +
                "PTDvwBNKdIcPwqFxPdbqtGOSVNxOMwvQ0HIjIekLxizD549oZnT0SX7YX7aeagCb\n" +
                "DJQ2U8MPbUltLSdyu/efhftZcE9PwhG9ubvu1Vo8J9kJkzN1BxXW7Ea9OLvYl9Ce\n" +
                "157zMYPTgetX3HBUUyrKmhoymSOoSeq9rRBZaORbO2Xhaf8txOk6yQuBatNMfdNv\n" +
                "R9umR8B+MwIDAQABo3wwejAfBgNVHSMEGDAWgBT4gi95/7R+CALbW68yneQ1YbVs\n" +
                "GzAdBgNVHQ4EFgQU+mK6vX5eX98fuge+H3k3gtz8EygwDgYDVR0PAQH/BAQDAgEG\n" +
                "MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqG\n" +
                "SIb3DQEBCwUAA4IBAQCPwnR8ERgKeZGYVBAdVSA3u8LTaxB1TTGBFNoTM2IzFMI5\n" +
                "xxmGkXSBnQUPLiGNAOSYuiz4TqzSZYkQvOYQVCowClplOKfi7jZfIBsU+EJOaX6u\n" +
                "ofcsrBmdY3hkA3MohlkWTwJY6J9O4OloQqBKwdFDTGnbeCk+ec8NVpBR2He9Nn97\n" +
                "XT3XrmDvRJUYH4Fi5mM27HIIo434Ncjm27KkEy8t4Ks+SXSMHBOtS4BgKivdgSBM\n" +
                "TWJbYv8vHbWBnQhFGbz6WD9yenm5ho4ejZFcIYGq9fJugU7j1NNo1CB7KIfCZW/E\n" +
                "Xog1n/lLdDgziJj3sYx6l2zR95MtzcdRRKlnyE3j\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkTCCAnmgAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTErMCkGA1UEAxMicmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NSBzdWJzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0z\n" +
                "MDEyMzEwODMwMDBaMGkxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRp\n" +
                "ZmljYXRlcyAyMDExMTkwNwYDVQQDEzBWYWxpZCByZXF1aXJlRXhwbGljaXRQb2xp\n" +
                "Y3kgRUUgQ2VydGlmaWNhdGUgVGVzdDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
                "ggEKAoIBAQDOcG4aw+WhAULnqHANEFgfOkbpQKUodW9QaY4fNaZozY/QB3qGOa1+\n" +
                "W6Mv3KoV3rEmzL7n/biP6RpjhY6MMoqD7S3sz0sbAxqeQeeY7/m0ScKlhtoiTcxy\n" +
                "ArrGpsOa4clVs8F7/8y+j+H3HiawKQ6nwYzh34INcUytlLd+G6kIT2y9J7B83a0p\n" +
                "HvxGVXAlVFUeUIZ1Nf75n/L0IEz91jBGHsrvvN89pGzLUPWCxh94EUeQ4uIawO4A\n" +
                "JMiGozWpVrF5YU3jztG77okNVxnxAPRRs8KLOhUROkmptAAF10oBR4Jw3kQNNF2q\n" +
                "eXwtCKv4naFajjV9yFoPN/wZTKDA/dhvAgMBAAGjUjBQMB8GA1UdIwQYMBaAFPpi\n" +
                "ur1+Xl/fH7oHvh95N4Lc/BMoMB0GA1UdDgQWBBTT/G30XBRLcdlm6LXjOmIn6MQu\n" +
                "ezAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQELBQADggEBACnxWF0ZZslNWBFt\n" +
                "vPGw7c4Ui3YQRuxEk85yOkTLO9HvymgskvkQezYTGQkYThzE+8T+VoW+XcGKtqzB\n" +
                "aWHeVu/S6Kq7zc7MbeHqC0vtyc3ViMFXk7Wk3gve6NBxwh92rITdtJFJ3+IAlmJe\n" +
                "RHgRan6mMujqLEZFns7fs/kIOiHdhB0W+Q/33X1AKieulxOlhilH8yM6dDBn5JaC\n" +
                "xVckbqTMMbeWzJU00zIz4oSNx3WvYQqyqrPVzCpVjqVFYJfFMs1FxBPNuPDovb+y\n" +
                "2Y8awekxYALnFyXfToV2owUFmK2BFQ62BiG9fghvsXWYjCSdcSdkaIBNTxbCITTZ\n" +
                "KFfbXh4=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(requireExplicitPolicy5CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(requireExplicitPolicy5subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy5subsubCACert).getOrThrow()
        val subSubSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy5subsubsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Invalid RequireExplicitPolicy Test3" {
        val requireExplicitPolicy4CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDoTCCAomgAwIBAgIBLDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIjAgBgNVBAMT\n" +
                "GXJlcXVpcmVFeHBsaWNpdFBvbGljeTQgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQDa+CVdJxQ/ByNBR6ZlsIM3/EsZlaS2iCQA2SxIP6w0Tc+v/+Ug\n" +
                "BcDBblSufESFEfbhmqzWITxUx4mourvl8nTWSvcUBXZITg/+9RKUNUAVvzCEEY6L\n" +
                "Yk1bCGInOwFe1QRA6q9bGfufN6mwbvwAYML1I6Cp9El/zpNWO5F3XTaIpJ6hWyXo\n" +
                "/FZ09MLMHhrAZKi5diInbH6pm8PYPtbAxA1GqjFmFQkp/idJ11sz0yL3Owbt3NRC\n" +
                "UwvYXdwGnpBkuXuDUEx6ImGT66AI9gSgVqXm1+hc78sElrlFR7JTNaaeulEAcIrO\n" +
                "XaijURKvc95snwvOI6Fcm3rMPq++hBB/P8uvAgMBAAGjgY4wgYswHwYDVR0jBBgw\n" +
                "FoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFM3R3MzUMWMHLF02sQ+N\n" +
                "nnW+S15jMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEw\n" +
                "DwYDVR0TAQH/BAUwAwEB/zAPBgNVHSQBAf8EBTADgAEEMA0GCSqGSIb3DQEBCwUA\n" +
                "A4IBAQAZdX7f0d/4NVR4jF1aslqeBmT4OLiV8GNLZjho/mBmhHqP97LU2aRMaAgs\n" +
                "xwbdMyffJY5yEGe/x+LEOD/+j1Zf5FOqwKXO3AesQqcrOVf94oAxc9qkMnbU5T3Y\n" +
                "S8DFSbvUqcPncCQ09UmdL+kcFg4t42WYige5MybEf6rI8bYaQuCn3R/Bj9QyKtvI\n" +
                "UOKYgJZS3aIEnwnU46I6Fi6c48r0KsFswpq1XLs2g9qnGYAQ0QTy3bZRoJHGUEWm\n" +
                "q3IlUK4FjgTfMWhicKyfm9HHc5mlM1TCLLAndyzhI7NSOS4SfRGUiSgrGydwkC9s\n" +
                "4MNoiNImgrIYopZynkesWA5z8HPy\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy4subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnjCCAoagAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NCBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMFUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMSUwIwYDVQQDExxyZXF1aXJlRXhwbGljaXRQb2xpY3k0IHN1YkNBMIIBIjAN\n" +
                "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjxAmVGJK/Tf1KXchcBFfOGvTNaC\n" +
                "PIrRtPoMudTQVaWVULbVkDlQlNs7U0HIhB5ojybvUweKYpmqMExSMVei4/KJwiYO\n" +
                "kvtLLlKL35LF0+lgv33qbmlhhE7GDg6XGc1edcu+Lfnn53F2/bpldSSwv040roH7\n" +
                "82NN5xqk8hP2iyChsb9eKFJolXo1opl/J7123xcUEgOQ1DEDTe1EKRGpcwguMk9w\n" +
                "OWz5X3fkZ7fd0WccqjaxX/e6mkNhTnnjHil7N/33FSOpO8gWeLBdy3hbidPWuBVj\n" +
                "Z6zQ3R4M308V8my5PpPjhkLuPoU6hRgqPXEQZa5CZTXWCnEvAGYmJsV4ewIDAQAB\n" +
                "o3wwejAfBgNVHSMEGDAWgBTN0dzM1DFjByxdNrEPjZ51vkteYzAdBgNVHQ4EFgQU\n" +
                "fe8OlBe79qeX5tgiSENIrLPuuo0wDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4w\n" +
                "DAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IB\n" +
                "AQBo1F5VotF+zBRk3lISLB+TwDbHkOnTeZP1CANWsThk/l5sx48F8cdhp4oqyzKc\n" +
                "aP/SjDt8a46clnd+jHN+WpaQComRwFNZFjytb4HRciU2QgC9ic4+L/xMG95pOQk2\n" +
                "ZAdzpa7SF5Nf8aR07Th3Z6gfSrMsN3KRurRTMWozjLaGXiOrrKEKARVf/AbytnKG\n" +
                "SVjB06e95i4k4/ge9lGKGPH1VajbpyZ96ujzVk3AB/hAY6q93nlOiSNATWa1HV6m\n" +
                "j29A6upj7f5E+SVd86Ms9TRT63Br/a6595avK+At2T57FaiuSHoPC+hMfq8hkLfQ\n" +
                "a3itQvRuWRzIOtSe6ei7vY7Q\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy4subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpDCCAoygAwIBAgIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTElMCMGA1UEAxMccmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NCBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEw\n" +
                "ODMwMDBaMFgxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRl\n" +
                "cyAyMDExMSgwJgYDVQQDEx9yZXF1aXJlRXhwbGljaXRQb2xpY3k0IHN1YnN1YkNB\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAym9lfJRPXHcjzvJ5Yn3L\n" +
                "WJQBzdL3kReoVmfz0fUk92PgyUtnYRyQZhOA4M3yd2/gui4ZSN/OdmhrCCmIzxE7\n" +
                "lqjxZk9wSZhdrNCC1dJRuZ8b/nu4Mu/zKUyj4OtbvsB2kxHLgDDVvD610+rqgpRX\n" +
                "INlRP03qpClgCRku72wF/cuxMYqtW8Ev5KJB5SV6PTCMe3IWkHb0H9Lc3Ux/fVgG\n" +
                "HW91o6bUrLbrqLkECrlz0l2pZ7DOuZgVQA2YRovfkajqmHJRzJpDa2dqgtXmIugL\n" +
                "lMdyeLG+Tv2mefGxnCotgiJoFJRg0rcooSt8sWYDOvyaFTZY/EIh4QbT+5i3bg78\n" +
                "JwIDAQABo3wwejAfBgNVHSMEGDAWgBR97w6UF7v2p5fm2CJIQ0iss+66jTAdBgNV\n" +
                "HQ4EFgQUqerm056wCZev5/4eLhAyoRBnTIYwDgYDVR0PAQH/BAQDAgEGMBcGA1Ud\n" +
                "IAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB\n" +
                "CwUAA4IBAQCqlr/tZaeY+Dfdr/JgHFg18fXEloYEoGqI8wbh5Uft00CMiLHIzQGl\n" +
                "sfDKHup2ZXSTC9IIbEHIw7ZVdztkvHEuuPBSny9GQv4KaB0adliyVaa3q8oYmqBJ\n" +
                "lgBoNi9Jz236otqmfuIuB/hjogNOnJJMzn+HYYgGdIWKiJj4pJ8CSesb/yx17Vf7\n" +
                "XgnyPxMeD9IZeoPfdGn/7tBM4Mp8TgnEFlaOujydYEj04+EjO9wQ5jompT+Z4xlJ\n" +
                "X5/mFZ1qhkxNzG2i4+aaRW13RW52bOzn29mYVBQ0YA8KIsWPZKqbTFDG9jEmdHZN\n" +
                "as/9IXJP7bOcwuGUljRq8n9O/M11poPx\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy4subsubsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqjCCApKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEoMCYGA1UEAxMfcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NCBzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEy\n" +
                "MzEwODMwMDBaMFsxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmlj\n" +
                "YXRlcyAyMDExMSswKQYDVQQDEyJyZXF1aXJlRXhwbGljaXRQb2xpY3k0IHN1YnN1\n" +
                "YnN1YkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2QXTxL+owEKq\n" +
                "PE3XYLeNLP6gbjf+741GuoCI9gb39kj0UpkLpXi1lrJ7gupEhUX7E9eo7HCCJ8ox\n" +
                "xuxAa/SgsU3DMLy4pEo1H4PuuhItPyqBzJxmj2urreCjMmU1WI3HiAjIIW1wrj19\n" +
                "Po50djXz6fMFhOZhohpg5EPK6XP8KqjEkKQS+bcXM49z/LtTQabfZTOYiwtZn7fc\n" +
                "dUjyGtLSCM+jnYqRgFRLjlDJw5SnVDc6X32DdskN53VPZDwEZEZZ+48gFr7kbj2A\n" +
                "TZ9Z32MGBt2iLEWCsxuZ5cntdFlECaCtgUiyibp5FpjJv+WyXsudJrDMP5ef0duP\n" +
                "tLn2sVw0awIDAQABo3wwejAfBgNVHSMEGDAWgBSp6ubTnrAJl6/n/h4uEDKhEGdM\n" +
                "hjAdBgNVHQ4EFgQUFLvRJvSegTyLDhLP2XsVsizcoyEwDgYDVR0PAQH/BAQDAgEG\n" +
                "MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqG\n" +
                "SIb3DQEBCwUAA4IBAQB4TRzPo/4HW8xacmWqsKY1hsa0yI99p9BoMHCdomXGM1Cf\n" +
                "6lU+wBWpRbwS2Vldrk6CqHpSUQ0iw1q/+WB4dc3qpTL46HzxhpahZ6t34fWUFB6g\n" +
                "04fL2oaRc8MNj0+dYG9FXo3X9ViBPJAP1A9o2XbuvBGAFjIIIL6TUxp66wfKv3c3\n" +
                "DxF6IThaOB0Xi/eHNGwKnyYAvdoJvx382YwOJP+0vADzr1a2kcCJdqh5fmYbyKUW\n" +
                "a57SRGJU2eAmHcoZbF4d6ypMuT6J/wzDyJ+0bB6AAugoffI/bsTcBbQwLaYMXbPz\n" +
                "Dhd0Xl7qLcwA8aVcrK2oBmacpLhjThEizNRm7y0s\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkzCCAnugAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTErMCkGA1UEAxMicmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NCBzdWJzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0z\n" +
                "MDEyMzEwODMwMDBaMGsxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRp\n" +
                "ZmljYXRlcyAyMDExMTswOQYDVQQDEzJJbnZhbGlkIHJlcXVpcmVFeHBsaWNpdFBv\n" +
                "bGljeSBFRSBDZXJ0aWZpY2F0ZSBUZXN0MzCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                "ADCCAQoCggEBANHpR/YhLPt/LkhU/hxCFZA3Ug2vdqoc9/PCCQcOHh3ZIZUPP03T\n" +
                "k023na21kRQ/hNBFJYm89nteKHb/f3RBBYsQtA1tHa0BfTWqesFZavNZF4PVwLpM\n" +
                "xTkJcxr8sXS6xX+SVIsEGkXgZF7zEo/SJ8Nk3nnP29uQyckOLlqF9c16D95JjlVw\n" +
                "7WAu+1B+mVJTIsztDkj5sPYzxYvvLLkRmE3noJgpoZ7HqMYB/mfocfqH70PsrXYh\n" +
                "ldQtkCjistQbF3uem8OEW2l1V+cWat954VUO/YzT1c3yqBD2tsJ28bMOadbkUYQs\n" +
                "RDEQYfXTpCmxAJa5GFtK0mn/N3k5CCjZ2/UCAwEAAaNSMFAwHwYDVR0jBBgwFoAU\n" +
                "FLvRJvSegTyLDhLP2XsVsizcoyEwHQYDVR0OBBYEFLIISgVhaKmQrx9w+bAv/uKa\n" +
                "AXJ+MA4GA1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEAVz36vPv/Ucy2\n" +
                "1a6sbkX49qaUfqge0g1K3YYOMRQy3WGfZlnXkbc82SkvgTOdzMBEIGmxGLrC7vkb\n" +
                "123Rv+nc6u2G0bninYms1u7qcLaGffjbtwEQxnT160WUvfRFkQnIx12mgkGmRS/J\n" +
                "GKcCKzQzLiiOwRwxjEJ1hJe8ZyrLlNa0BdqG1i9UrBzGzIlF8w1S/ObHBhH28wVz\n" +
                "b6gbo1HMT+I09piqPOjDsZF8Zrzsa3fn+uGfGZarNHeK7oJlKoJDYWOG579cxNXF\n" +
                "YDKFJ3UghQcXcZWidGIgFfwaW2/yFt6y5a76nb0/1l3CF0G/xkuRI2IROptfdsh8\n" +
                "o5ZpO/ZJkg==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(requireExplicitPolicy4CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(requireExplicitPolicy4subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy4subsubCACert).getOrThrow()
        val subSubSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy4subsubsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid RequireExplicitPolicy Test4" {
        val requireExplicitPolicy0CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDoTCCAomgAwIBAgIBLTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIjAgBgNVBAMT\n" +
                "GXJlcXVpcmVFeHBsaWNpdFBvbGljeTAgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQC9H7tvssdc/wduqx16T+W82qMWJRF190U8Ojp8YtO11D+dXuos\n" +
                "YwW1s2g6HC9GuoMCVkS7H3VOx4D0T+oY/Gdt2vVKWFALPXlPkXYvcetrZeBucc+8\n" +
                "oQHdgUeMKpFwagazoOeBZRbEKuz32amMQajto6RsdOKn8G/tCfvPWSiu+e9Wpr1A\n" +
                "F8/F49mxKRrHo/8sLnHZEBYA4NIVy/KuXThzkYmfU1nfVejYjNPDC8rV67MtDvJX\n" +
                "Q4KkbASnlX9zzaQuJbT8AeUeDMnYKbss9VcWTuukIk45PMAJvF9tnK3vlzPZcoI1\n" +
                "wL8Xznd7XpwGDCjt9sjcfFG+P9gnnpe+oH3RAgMBAAGjgY4wgYswHwYDVR0jBBgw\n" +
                "FoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFLns37pSIri4vmr3ohLV\n" +
                "JyDWZwQ1MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEw\n" +
                "DwYDVR0TAQH/BAUwAwEB/zAPBgNVHSQBAf8EBTADgAEAMA0GCSqGSIb3DQEBCwUA\n" +
                "A4IBAQBW5W0it/x9piqf4Ontkmv47v7kAheDZ3zVTavuaSyTR3X8zZjq2MRZ/GP1\n" +
                "ukAIbYmtVA8ButPfrz98zK+JvgWhijro0lulYoB1weRwEVCCskRw1puGCwLcO5HH\n" +
                "esqtSf25opakP+8orfdJ5oz3MNgIbV2eLrV8UBoIwqUlh9nJur1dLYY0EVWaLtl0\n" +
                "vG3ZCzoJUdoQfidcBukQ1vs94fSeo86PUSmc3ly9R7e9bqmlYx3W8+UWWnNzj45c\n" +
                "7kho7OxSoyZhcIP30Brq567uvhWftpHTThNdgsXLEMZ0sAtYz3RRTwJR926fij54\n" +
                "sXrppFJp8OTTFV9u++k/u3qmGQJq\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy0subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnjCCAoagAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MCBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMFUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMSUwIwYDVQQDExxyZXF1aXJlRXhwbGljaXRQb2xpY3kwIHN1YkNBMIIBIjAN\n" +
                "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1kJr6U09z+r8aR+1RvhIAo+D0AF2\n" +
                "do7gCMyAhzT3z+LRHAdHqeOwpsUaTBcREVV2MsCoWAk2gsG6mkXzrpKWWboFM+0x\n" +
                "V2HmWjDSb44HNYEwcnSQ8uW2eIZ/B2ZUEdnkODBvIToPEbvfubccCBz+zerRuShN\n" +
                "yB/m6m/Hgx65/ZmLLlja62OdP8/Txk+q+NudnkgkWIFaoqF6PxPyZDf5rS6wFybi\n" +
                "B2E3xETVhRSAVuKqJXiTIl+xQnc68/HaF00Oj6Ul2v3Xmy8pLdA+z+BMBLEgso88\n" +
                "4CQCCw9DKWExeWOGTOGcsXGF2Ccxo+HjIpDtuy+NiyKBrCySjJWTMebUAwIDAQAB\n" +
                "o3wwejAfBgNVHSMEGDAWgBS57N+6UiK4uL5q96IS1Scg1mcENTAdBgNVHQ4EFgQU\n" +
                "vmJ4/Tu9bpwLM/I7MqpBCPPliVowDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4w\n" +
                "DAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IB\n" +
                "AQC1SY78Ivlxwfun6e4Ru6ZfZbq41Jdn9WDMSO2BpepubxaXSDmGv0lGuvTDKAJK\n" +
                "qNLUZ5GfGJP6inTx6iOxSPsn94vVT3YnlQNB3m2BW80MAL4G1Y+2IGid+DziABjl\n" +
                "uuihKKe9gSbu5alh39RolvCP/PuUmXX53SJvn6rcM2ImnP80F73lccJno+on/zX8\n" +
                "SvLqoGBA7jUO6XUJRN9ZweY7jpjQmJkRbArIHf8XUaEHDzFnn9job0siFYBfSbyE\n" +
                "zDGOqpesAx/2enD3AHGdCQAfN6j68bojseeY+o2R/qKAyW6Q3tgloj33bo9xq4ku\n" +
                "qNvqfPmXIIdT6aO4zpTrjJgy\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy0subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpDCCAoygAwIBAgIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTElMCMGA1UEAxMccmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MCBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEw\n" +
                "ODMwMDBaMFgxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRl\n" +
                "cyAyMDExMSgwJgYDVQQDEx9yZXF1aXJlRXhwbGljaXRQb2xpY3kwIHN1YnN1YkNB\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu2JoTDyKgPYRFw7WI1x0\n" +
                "qDLxFwPdMWrqDNPO3IXgWvoxaJs9TTJ0Du0yU4WBqNRR6waqPeRLtXi95RVg60CG\n" +
                "EEbY4j8nTVNGj0VUnDfF/ey1ZrIPpLh2HWE0UGAfYPX26sZ2Z+gN4A9KE7kRBgf0\n" +
                "GfwwebdVRJq4yCncvmMqAevllCUonA45cn3W+wC9n5Ono4ooD4PJFJ8KRALImUXc\n" +
                "xHFtvL4GEsCEHHXFrEGle18aQiApb1aFVl1USk59ILLs/IuFdf1J/pztbA9HGEsa\n" +
                "w0yrlN2fXK/ZPZhyD/Bs5Wy8uH85iduCRgmRa/XENqccN7AxVp1NeE8OxW3rjEQ6\n" +
                "VQIDAQABo3wwejAfBgNVHSMEGDAWgBS+Ynj9O71unAsz8jsyqkEI8+WJWjAdBgNV\n" +
                "HQ4EFgQU69iXen96IzUZ5M+XJCcizGenVkkwDgYDVR0PAQH/BAQDAgEGMBcGA1Ud\n" +
                "IAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB\n" +
                "CwUAA4IBAQCVCnP34O7DI0X1maCMTT7+hJ1cLO2LvC5MlQK8q/V/BjKFc6G8VcCy\n" +
                "SMRFEwgoMIctfF9lWLqFFGlAJPB1U6T1w80eFb3GCB9vLILx5rAZ0Zib963MzFZB\n" +
                "/hxhpnmwAQLc08zmjtHQQKNiTOWKCriBfPvAMGbdWNej/rwnDSj9YpBBEYE9Z4AV\n" +
                "EFUS6DTBCj4QHP4Sej0y3V/MJot1F18U7Q3UCGicrrTnQrtP9g+r2dfRruaNeoxc\n" +
                "T6YmhEvBrdCwoAlBFpBZr0HAI4+iTMB4Qt007Tc9WG/zH3cdkKH5YsqRGIr37Ruq\n" +
                "DG/m3mjqG+3WkRuj1ExY0LYkxxiMdCVR\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy0subsubsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqjCCApKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEoMCYGA1UEAxMfcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MCBzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEy\n" +
                "MzEwODMwMDBaMFsxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmlj\n" +
                "YXRlcyAyMDExMSswKQYDVQQDEyJyZXF1aXJlRXhwbGljaXRQb2xpY3kwIHN1YnN1\n" +
                "YnN1YkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4d8UvN3QmBtB\n" +
                "KQJSFClF134Wrv+NsPbS8dsXxeWIPKizD+8yDP53Rwdwr8k7q+Q2f3jZdXWovp/Z\n" +
                "RILL+woH9SRbSNRpyDPtbrukl3hPaUO9UCtpeCqPETb5/zfJuw8JIqSG9Ab+atqa\n" +
                "97bG7XzBTThsSNkfckHoDAc8i0U1HngPuLx9elndglmKtlfgKGqTagXLaWJbo0WM\n" +
                "phT8BOBrmBohhIr7K+t08MyC72vCLZXD4dTkV/+fFuhHdKOP7XHNejLOdy8QVbC7\n" +
                "kuSTPuCjI7a5EjtpSVwpXvpaooHdFIeOCiPjJg4xBP1NNJuqKG9Bkc+P+dMjdz+i\n" +
                "JH4ybXFsIwIDAQABo3wwejAfBgNVHSMEGDAWgBTr2Jd6f3ojNRnkz5ckJyLMZ6dW\n" +
                "STAdBgNVHQ4EFgQUtdsE1sggCC9aQcd4o0SJ2s4ua7owDgYDVR0PAQH/BAQDAgEG\n" +
                "MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqG\n" +
                "SIb3DQEBCwUAA4IBAQA7RXTh5JOGumpqPXnJxJTJ0T99+mGke4EtCkyzmb1KvyKD\n" +
                "gId0UwrUjENlGX20Jqt7/PhBcYS4xgx1kpQcRf/WJ8pzQbSH7SD7EFxySJ4d4zaj\n" +
                "Zu9ITjJCEWw8qlWRP9lbQ5Hucs+X+W1kFSlWM3GgV3qcysDnNlcBoJfpNC6wehFy\n" +
                "aSIBDY+SgT51bDZp/ANdKUSIjX1HUV6uRzCPQZYKkNAD4hS3X6as37Ap5WerP8Lf\n" +
                "rZKkEtbFFB5TSJif31LTsxb5sYc2AtBjOBKvemBGzdmtjOs6MNRXvRdi/wwK3wJ5\n" +
                "Y/y6tuaxlJtlUngvx7HLQxlZOvySQrq84uKZ3F7C\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqjCCApKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTErMCkGA1UEAxMicmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MCBzdWJzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0z\n" +
                "MDEyMzEwODMwMDBaMGkxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRp\n" +
                "ZmljYXRlcyAyMDExMTkwNwYDVQQDEzBWYWxpZCByZXF1aXJlRXhwbGljaXRQb2xp\n" +
                "Y3kgRUUgQ2VydGlmaWNhdGUgVGVzdDQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
                "ggEKAoIBAQDeDxXcQyw8uZzj9sUOQ/0sZRELT3exJGteTsgMGmazqaA7z6mdqc+Z\n" +
                "IN/6xj0Ub61biiNXdOfGAGwd+l3mdx94E33ik+1zylEWJqyr2Ovc+JcjR/z6IbcN\n" +
                "Wv6FPdMPsDTaJgERvuPm2dPYViKpRDiV4BTQ5DsrGhstJGsT/K04UiIB6ahZKN6/\n" +
                "ToL9OTp+Sj+Y4DAyxl8MdmQWgJpzmo4yeDroGyA4Ui6nTMgVcK2vPDti7o3yjZVe\n" +
                "rkAqf59Qf6PUtsUXl+eprAQ6gfV87Z8/3K0d/n7QnYg6KcAIUxAnwocuJOp+TqFV\n" +
                "W2+G9ArW8qdpsLmZqUtj/h+STuUj30mxAgMBAAGjazBpMB8GA1UdIwQYMBaAFLXb\n" +
                "BNbIIAgvWkHHeKNEidrOLmu6MB0GA1UdDgQWBBTSKJ6JK4Bv9B3Im8QAxcOiq9ML\n" +
                "DTAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqG\n" +
                "SIb3DQEBCwUAA4IBAQCTBUOuvyS5e9eevtUKsjCPLpfP/Daf+43KMxHIvLUboO4B\n" +
                "8KWd/245AIioGgK0vr1AoL0cvOyyYvKuSbi/j/M9WOzCCmgrzrA3mWi9IHq3gv8X\n" +
                "zWag7VWx4fVbQVQrqseyAKouMZDqWp/rl++IbittXlhcHi54qZ2LgO9gydA7pXN1\n" +
                "9LOpUOi0mP0wFDfDoOpiNOGJHg5SLuwQWFtEzcXrqJsjtoNigtpXeY1S0nt9u5Dt\n" +
                "FQVk5FOD7S7SKIuy9QVuCDelDxFYU7zOGNq229S2yTa9dJVym24aGsrJU++XVKle\n" +
                "FM2quSZqdJ90IpQS3FMQu5XIa3iLaiMNkHUZStnL\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(requireExplicitPolicy0CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(requireExplicitPolicy0subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy0subsubCACert).getOrThrow()
        val subSubSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy0subsubsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Invalid RequireExplicitPolicy Test5" {
        val requireExplicitPolicy7CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDoTCCAomgAwIBAgIBLjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIjAgBgNVBAMT\n" +
                "GXJlcXVpcmVFeHBsaWNpdFBvbGljeTcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQCpVKpHFxYwg5kq0aETF4qFIYC1k132i1tnGPJFaE8s4vgtocrS\n" +
                "wVS8gZ+IUAcAobfNjTFJqLkg+Dir5O+DrUmbd6+DIrw0EJL/O57bC94jTI01Cl6w\n" +
                "O1sVnY9ni5yFDZGQiE9iMBaJQ3UBrGMSu3pT4lgV0FzEet70qnE2T8irAWid+7+W\n" +
                "9cK/RatZKF7F/QjgfYO1giZs0S0bFt+j4jK7ZQPbYbnLR93hZziy0di4qnr9U2vs\n" +
                "ekYlvwNcsjL7H1SqtCo6bwxL7jXn0GTpZz2O5Pv7J5xe69nW+9uULcCmYgASUJ2u\n" +
                "exqWd2b15Eb/6qnnoPYPojIwmyuCjG6hVhj3AgMBAAGjgY4wgYswHwYDVR0jBBgw\n" +
                "FoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFGwxlwE1IN7bNeUKaVhZ\n" +
                "iGTMIc5KMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEw\n" +
                "DwYDVR0TAQH/BAUwAwEB/zAPBgNVHSQBAf8EBTADgAEHMA0GCSqGSIb3DQEBCwUA\n" +
                "A4IBAQB0FCmLk1xVqT7ECIhn+PfIXXQ312OWKRKqZurBCs8fMa8zq67GVBFi2HEo\n" +
                "+TwXaN0u3G5q3esDk+20ontt7cxaTx416Lnd1i+6+daK3ieIbvsX2yE/f6zxmRwg\n" +
                "J4B5UTFm9yrhJHHn8JSyNKNFe33fFHWcUM0MuRfRNK5O7tawg6HlILr/hbPvO0Ls\n" +
                "FbbJZyAzCHBqL0x9GS7pyFNJub3Y6BjYMLIvUNKbSaciw/rYLWEuV1uVyD3mC++4\n" +
                "a2MeiCdQfFDki/xaHElme7qkiQeEDaUXCjCQ5m2Bhl3SMo5g/8SVDs1l/012UfsH\n" +
                "uT4wf2kqJcmh8a5OSvuczLgsCqFm\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy7subCARE2Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDtDCCApygAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMFgxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMSgwJgYDVQQDEx9yZXF1aXJlRXhwbGljaXRQb2xpY3k3IHN1YkNBUkUyMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArNCCh87bZLO+YSdMLvfXHSR9\n" +
                "pno7RfOAsEKaiPo2ievBaYHZUI1eXBOi10V3Klm+WZ7kGRKXr3ZjCxBJ0eAbUav9\n" +
                "htXPdQprkjHS6+PfehpUiZvoe8JM1SaEIk6ZJ6hZbWQ9fL7xsCy7M2t1mPnFuN2i\n" +
                "23TbHRIOmkxCD9NJgDqejNCN9O3lqjr+na978Irf3ZrSK9GZ9LnopXBcg70DcTMg\n" +
                "TcuCHfPuvRyciClvMAFUaUvMH8POVFa6yDriD/ArHXfc4FLTFaLMN57lah8ft0uN\n" +
                "+Ec1tvqnSg7mDcHN8jdyj8Tu3sjh23QHCyvlKJUjk2FwLzmaDvhn8KIS9pPVBwID\n" +
                "AQABo4GOMIGLMB8GA1UdIwQYMBaAFGwxlwE1IN7bNeUKaVhZiGTMIc5KMB0GA1Ud\n" +
                "DgQWBBTnXCWOfqpMd4N7w+pp1seiNOE0WTAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0g\n" +
                "BBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0kAQH/BAUw\n" +
                "A4ABAjANBgkqhkiG9w0BAQsFAAOCAQEAohBJ68sra6KMs8u+uyx1e8HRXv4rsIM9\n" +
                "vc4H+OfqE3OxVBT/xX9QFx3QtBAKr6x0BKRZAxQwYi4bCZilSUDbuE/WF/fv21k4\n" +
                "fVF4R2W9uvo8pKwizRr5/cPEq/N7tWtv1YhilcD1ET/k2RoEIUtgsOres7iQ1DLo\n" +
                "O1t3u69jgi0UCEymRrzr/JPW9nLSkNYvr+M3noFfsYxeNb81l2Ma89tOdZ4dixNc\n" +
                "tsYCgQ7DP6IEDdCpUxY9iEjnZHYGW84jIvGNQ+ASlx9R3WNuQm8QThxbdkAJhDLG\n" +
                "PhoYnJE7zsZXFhvQGh8KWxPCN5F04yl6mEAGE09OU9fv3qOqzLlgQg==\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy7subsubCARE2RE4Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDwDCCAqigAwIBAgIBATANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEoMCYGA1UEAxMfcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NyBzdWJDQVJFMjAeFw0xMDAxMDEwODMwMDBaFw0zMDEy\n" +
                "MzEwODMwMDBaMF4xCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmlj\n" +
                "YXRlcyAyMDExMS4wLAYDVQQDEyVyZXF1aXJlRXhwbGljaXRQb2xpY3k3IHN1YnN1\n" +
                "YkNBUkUyUkU0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsKLzquG1\n" +
                "Wxpg7dOJrrPXsuwroWJcJ9q4XcofFyo8PWBu3Yt4H4H8rEtQATDnOcorYd93IcJx\n" +
                "ycuxyZwa+PQEGZOBZYAtxyicombbYGR70wJ1Njxsa1oHKe7wFGd6YdMB1xbFjNqx\n" +
                "w1umyI4zvGR8WpfA0sEUilIF/sZCcErVTk7fDNi/KT3BLyyDmQ8sHFhQqxL9i9FA\n" +
                "tHLHaZ4zyH0HgXGgUEqblgw+wsWWRQVP5AW12UaALGLn4ZijThUihW5H4Khx7pcv\n" +
                "Xq8oZsLjbWa8wR1NNfeZxyd5qAyEYKf69/53vKjDlcDCaZSuM+Av3r1x56+VpuTo\n" +
                "37CuXylUcS/vewIDAQABo4GOMIGLMB8GA1UdIwQYMBaAFOdcJY5+qkx3g3vD6mnW\n" +
                "x6I04TRZMB0GA1UdDgQWBBRu/40Ii2b+m6V7+2QzZeoDlUiUmDAOBgNVHQ8BAf8E\n" +
                "BAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8w\n" +
                "DwYDVR0kAQH/BAUwA4ABBDANBgkqhkiG9w0BAQsFAAOCAQEABhL0Q/1K3/hsd6Od\n" +
                "6TGkaumY47BYBh86RHtxAoGKXecsotYO1kdJXLQsQOkEpLp/g5Tj0WL2YqX5tgS1\n" +
                "r8fkcfAL1+Mm7vq6UEBd0S/wLZndMJ/Xjvzpal/o6iujqIEkWZZa70hYRcN+Q/OQ\n" +
                "azhPsDKAm4I48xaRKOorCVq0PAjBwRia8MucOcoymmiQW8/wQWS3fMRj1gh3DERE\n" +
                "Y/6TLeib5pyH1KYXE7W7dA76K9SzX7TlDOFd3xybch1UxTrz2I9cqbjQdDjJMEYU\n" +
                "W8tFdCcIk1/dr2faOuWvKkOw+AQRKciVrPTRcb/GKKlnNhc+YRx3KBBs6D2kjM/O\n" +
                "hsObrg==\n" +
                "-----END CERTIFICATE-----"

        val requireExplicitPolicy7subsubsubCARE2RE4Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDtjCCAp6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBeMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEuMCwGA1UEAxMlcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NyBzdWJzdWJDQVJFMlJFNDAeFw0xMDAxMDEwODMwMDBa\n" +
                "Fw0zMDEyMzEwODMwMDBaMGExCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENl\n" +
                "cnRpZmljYXRlcyAyMDExMTEwLwYDVQQDEyhyZXF1aXJlRXhwbGljaXRQb2xpY3k3\n" +
                "IHN1YnN1YnN1YkNBUkUyUkU0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
                "AQEAu6hakMgtlNCA+rCJWAL8vGJ9le47WEg+7fAOpHBMAZvLGYiufTGL9z082H6l\n" +
                "XMYJZl9vt/04HghPEbFeWfF/S8ahz6A7kpuSB/i4trfzkyCYqi+5YDozDw3+JzVS\n" +
                "C9h77p59euEO4LVxlJwxLeDIXh2idbYmMs6hBqyktdRv4qZbqgtAyascshbclgs7\n" +
                "5YJWYtkDp59/MWooX/Af8VNTnCUGrgCtk7dagQd1eGilyo0NpM6XDQ6eYdkqQJhI\n" +
                "zyvGo5SWSAmkIrX0fRoyocwD3ibn+OUN5pVDZplzYA/PPL4kq0BBFt8C8RddSZIs\n" +
                "1YM+hnhSdB8mRfs/Yl/xWpIwhwIDAQABo3wwejAfBgNVHSMEGDAWgBRu/40Ii2b+\n" +
                "m6V7+2QzZeoDlUiUmDAdBgNVHQ4EFgQUeyxRYTEVrawsa6m+OzsYGpKqf0QwDgYD\n" +
                "VR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8E\n" +
                "BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCcmQxvc23zsZ5WsaG6itcxVmsRDeKF\n" +
                "WjkeTATCwuac7OTFciIJ2ts2sMDnT5yupQFxNn03VhBejR+caA2RlIKkV31tQDu+\n" +
                "34kvGxD6fLcjAf9tfUbzjfEyZEPAfrlSiXVDLVPa0BFw/mO3gjCNNlLs8/RoFhsZ\n" +
                "alMVnfklprdGkaGldVuqDDHPbiX2xy2WE4XoWKSqD/PXBifml/K8Ktfz6FezN8fH\n" +
                "DIz0zc7JXnu8mI3TeWFSvcK+lIBVfmm3sarVDGVR83/RY+ev2kPP2PzKL2vJpBqD\n" +
                "cRKPCxQiGmMw7IaDw8o/mGzapGd+W+zIgL0G/cvtbIKayoe7fwk9iHOm\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTExMC8GA1UEAxMocmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5NyBzdWJzdWJzdWJDQVJFMlJFNDAeFw0xMDAxMDEwODMw\n" +
                "MDBaFw0zMDEyMzEwODMwMDBaMGsxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0\n" +
                "IENlcnRpZmljYXRlcyAyMDExMTswOQYDVQQDEzJJbnZhbGlkIHJlcXVpcmVFeHBs\n" +
                "aWNpdFBvbGljeSBFRSBDZXJ0aWZpY2F0ZSBUZXN0NTCCASIwDQYJKoZIhvcNAQEB\n" +
                "BQADggEPADCCAQoCggEBAOKog33tBMcvKLdCEtAS4Mehc0LTwRfbt/eJ49owA2W/\n" +
                "KSzT9XiKoZ7t1s7MPh0NfAkOu2YOlqjt5BOSlzQbQ57h+/3lBdMXkNBT3YEAsrgo\n" +
                "ADlhGA6CVOIxPuZs7z2x+ux8m8wB54ZXO8h7JFfj+YrIKkMoTvePMltatxlox76r\n" +
                "TUK2LsXOZKbYZBkKZEqtIUudUcd50N/WTkxg5qE2Up9V4oXhdY369sF//7mMadZ5\n" +
                "KDBqDmHC3q996y9CERPghc/sZQVaX6widPtlsI+SO74IBMwOX29eIroug7mbeE7L\n" +
                "JFQc1KYaGyB+Po29y9l+l6C9mfWOHeMLKOCzBlexG58CAwEAAaNSMFAwHwYDVR0j\n" +
                "BBgwFoAUeyxRYTEVrawsa6m+OzsYGpKqf0QwHQYDVR0OBBYEFLy7jwxuDW3P6K0Z\n" +
                "wZCQ6vgkqxIEMA4GA1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEAjMJa\n" +
                "DaSfZMbvgS2voQaA27koy3de4DX/dlI6a/QG0O2HHilgp3g1/G42thy90ewLvNse\n" +
                "nkYf0tFM0Fhx3n6KwNTf1nItuwn2HwTIiw9jQ/ERwLqRzmnCor1fKf+maNGWqYg0\n" +
                "vFmmrxVo897hX/0b9CFTpS+SP1RgMonaVnjkR4/sA79aJ49wUpdPkVZrmXOAaM8r\n" +
                "MR8ryNohpRY8U2O5+S8MJZRKQEDyMFW0kXeC9Otngb2h4ORErh09DHI/xuGN15So\n" +
                "90UadDApAMpCi3PijRNIKVcBpge8sAvXwR/iYX9ws8XNuJVkEGYQYJwLKU3t1NAA\n" +
                "Ynvjy3YgibsBuUcfng==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(requireExplicitPolicy7CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(requireExplicitPolicy7subCARE2Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy7subsubCARE2RE4Cert).getOrThrow()
        val subSubSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy7subsubsubCARE2RE4Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid Self-Issued requireExplicitPolicy Test6" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlDCCAnygAwIBAgIBAjANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZcmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MiBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMHUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMUUwQwYDVQQDEzxWYWxpZCBTZWxmLUlzc3VlZCByZXF1aXJlRXhwbGljaXRQ\n" +
                "b2xpY3kgRUUgQ2VydGlmaWNhdGUgVGVzdDYwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQDbNiXBm0YtSk/Ghd0P94U5XcIcxuUottE08ezytyJXoHrNGEdQ\n" +
                "qr8VdETgymFh8mzVUeMJkcid8m4WNoWCRgLJ+79DRInPxLrJr0iN/A+KFE4JmtKr\n" +
                "cshTYXlFRZ2gNdgDtkQ/zS5ZbkssumE/R4Y8RQRUeSTu2VdnRMaAb/Hey6UWvv8j\n" +
                "cm79m4y7ZJ1m7Q5nykQkzrerHkdSM+9a2d7gQzWxMqPYZr54VEoKHfsWCBpH6vPt\n" +
                "DfahIBmc0wkScZm3Vty6ILpYqx1dCbRSC1jz0gU7wgCq0PLVwWksfs7uO4XSSIji\n" +
                "U8tD6x7fkn/KiecfEJ9a8T08CvnBB8ZPPY/XAgMBAAGjUjBQMB8GA1UdIwQYMBaA\n" +
                "FO+r2tjhgDGnQxbuxHYNr+xt8mChMB0GA1UdDgQWBBS9gn/7u3AKjxkoylIClC3A\n" +
                "ACjrnDAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQELBQADggEBAD3HVKAawDug\n" +
                "wgfgCjV7A0Po2oPtZOUMiOH00G02Fc/T1IoC3ni0hzdvJgKIrO+IWoQxLS6+bLQ8\n" +
                "fndqwupJZk2KDKsry1moOVb9opimfZzDS63709qvYJsL5ohMO0XkUk1iBNaNv51X\n" +
                "e+0+Mn4HRONt/hAITzlFt6XRXkETiF1Pfo4Jt3S/iNvhMmqLfiEPIckqsY7wv58E\n" +
                "ZAgcxSBEBv5X2Y9RWcVLYzw5Q4v0b3BDJZUOdy2utVdQiiLU9YHTBioGqZLo5VK9\n" +
                "sfW8eaF9X5sR45YMMKRW6O274Ns4AterwdcfIJ6lKUbBYhV7TR3GBTe3oO4gH0kI\n" +
                "0tAWe3Zf7g4=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(requireExplicitPolicy2CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(requireExplicitPolicy2SelfIssuedCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, selfIssuedCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Invalid Self-Issued requireExplicitPolicy Test7" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTElMCMGA1UEAxMccmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MiBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEw\n" +
                "ODMwMDBaMHcxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRl\n" +
                "cyAyMDExMUcwRQYDVQQDEz5JbnZhbGlkIFNlbGYtSXNzdWVkIHJlcXVpcmVFeHBs\n" +
                "aWNpdFBvbGljeSBFRSBDZXJ0aWZpY2F0ZSBUZXN0NzCCASIwDQYJKoZIhvcNAQEB\n" +
                "BQADggEPADCCAQoCggEBAMpH5Ypo+vnXJBia4f1mbnxhkV5cPzmsJbefrK6N19Q1\n" +
                "/eCApM79FHX9P+kh0bZnbdbjXiUKwNsQc9JAG1Il66+qu9bfOvF73Au7qAvYH4Yh\n" +
                "bAvpARaQZD9sIXjUfOY1t4NK6uRdNOSoykfpVqwa2GhsI2NfVgKNzJj4HwO2/k2c\n" +
                "qcOUTds82VbcOHM9Z9AcXwK4TvQo6gUs0HkNNXVO7Vj3+Y4JXG5BFG0K0xoJT1tj\n" +
                "M4ZKn1z29+TOkIDoYD9qM2ZGVMGhDLam2+OXM/f/d6C3eVGMBc4wLPYZxwnExrwY\n" +
                "07GQUBn6dgM2DVMY7BDVqQG8frfDa4kIZ+vZzD9BoysCAwEAAaNSMFAwHwYDVR0j\n" +
                "BBgwFoAUIHf+TDCN4rNRHY+w9xx/HYOYDkcwHQYDVR0OBBYEFBdp3Tg8vwRCOWFC\n" +
                "TfeJoRRkfWArMA4GA1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEABr0a\n" +
                "hM0sHQk9v6Z/9xK3gKE0iphqV5SrOUgtJz/DBzm2VapDSY0No7dTsSweTR8toL4f\n" +
                "1ynzt3V8u3NP4Se82nphDaFD2eaUDnGWcFCj604pfhlt+rJtjF1mWgWAy6HQP2qf\n" +
                "5+jhDE+S0AqqlOwlkj4wVEVlodDTUJyeU54kR2aUIXMTs/OD2PtNJ+7w0Sl9UspB\n" +
                "SBuiJ964Qi+MdZRoFOpYCR3avVagU3CpURNyLm/l5rNu15sbnpFLhCsDx2jffIGP\n" +
                "yikRtq3rrmY/xeGj4lX06KJkOCa6jAjlZEjlOPDXWOZtx93nowyliPZI1yjVfCYj\n" +
                "zVx3huyEnj+ozMCnlA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(requireExplicitPolicy2CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(requireExplicitPolicy2SelfIssuedCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(requireExplicitPolicy2subCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Invalid Self-Issued requireExplicitPolicy Test8" {
        val requireExplicitPolicy2SelfIssuedsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDoTCCAomgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTElMCMGA1UEAxMccmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MiBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEw\n" +
                "ODMwMDBaMFUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRl\n" +
                "cyAyMDExMSUwIwYDVQQDExxyZXF1aXJlRXhwbGljaXRQb2xpY3kyIHN1YkNBMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwnzSUphT/R8NNpeCrM75XZbe\n" +
                "zrzFry7FcZWWHSFkNKZPyzKJiHyA4uWR2tIz4HaoNR31abyitlqnK8raWcRobhY/\n" +
                "v1YcatsWBl84DXeUijt7Lo8FsgFYgJtXdQMTTZM09lrY3YA1daUUxjEVWxogoFVK\n" +
                "mfAz1lLiAlMEeyzWCGpKS/RGY3f0AKZNLFFqcaK7bvWOcg8MJezmWGd++937utjZ\n" +
                "tQDLzQ6m4I9pkrOQgwyIL0BTetwyLG3wMZRP7nhU4p4BRoSDfMiVQ8Q+wWKWIl1+\n" +
                "EvRdNnM9L8TJYtBYvFDxPNIHlqi2OKi8burXeGaHD8MkuQ3/XvaCCoFLz465LQID\n" +
                "AQABo3wwejAfBgNVHSMEGDAWgBQgd/5MMI3is1Edj7D3HH8dg5gORzAdBgNVHQ4E\n" +
                "FgQUSQpnYVZHjdJZl68iZjBRd1Cq3KIwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQ\n" +
                "MA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n" +
                "A4IBAQB0287v2B91j3aqGz6VvjWX9dV1aXfrJ/agTXML2eCFfDpdZHSJBfF1eEWp\n" +
                "EyRV5B4drAJJUOFQk2A576yH2wY26c2CatdTtepyvfiNa9j5KlxF0eJDuU7RjIpS\n" +
                "X9aV0yLZVWj+zDxNZcWnTZiw5UmEURQWm1UvNe4n/DZqP+Pl90VhHmQujpDNRzsb\n" +
                "zKmGbTwGtJ1T9oEIsP++cRW+cp3MXY+31gYghwsEgIL974tnuHSSL/NTM1lEu6VF\n" +
                "A/45TkZKj1ZlQPYZmG1AoT1JeAoXoWDEoqYpXNZoQAD5fveEtunwPb3Ndy9GRvuV\n" +
                "r2lfVmqh7AmOZMnyQvkxHohQ3cY3\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTElMCMGA1UEAxMccmVxdWly\n" +
                "ZUV4cGxpY2l0UG9saWN5MiBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEw\n" +
                "ODMwMDBaMHcxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRl\n" +
                "cyAyMDExMUcwRQYDVQQDEz5JbnZhbGlkIFNlbGYtSXNzdWVkIHJlcXVpcmVFeHBs\n" +
                "aWNpdFBvbGljeSBFRSBDZXJ0aWZpY2F0ZSBUZXN0ODCCASIwDQYJKoZIhvcNAQEB\n" +
                "BQADggEPADCCAQoCggEBAMy56QuuWL4z4T/hWo/3VB/kVEeDeGVv1rUBciSdtpBc\n" +
                "G+dYzJ0Y4IhU5rTLKjCPgL9NWXJAlZ1xCHG1NKDtNXKhXFtWUBvjGg8cVn0K3g8Y\n" +
                "FMOR9rxiDaXyzTQSBSMhUXfyc+T93eyt5OdlKSh5dljxtLI4L3UZunZ31hqCOxTd\n" +
                "N41T7S7XBKlmFnh+ICv44ApWOxndOjY6X72Yfgn1JOaz52YyDDRK/fLzSevInhee\n" +
                "IJVfWEqj3nSZ4SK1AFGID8JK5yxhtO/aa0M92TYNCBZDJb+Ow1aA1sS1gAt94kwV\n" +
                "4l+VBqmLyJehvfNfH3zYDGLDN0AQ1Pt6bsuEu05JrKECAwEAAaNSMFAwHwYDVR0j\n" +
                "BBgwFoAUSQpnYVZHjdJZl68iZjBRd1Cq3KIwHQYDVR0OBBYEFMgulWC04OIHYKL5\n" +
                "NsodeizMbr+rMA4GA1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEAPXjo\n" +
                "buDiYyD2GJrx/C5uDJWDWnvG8RQpPaPjexNQqyOXqopA8g/64QkBZHnzfDtsxmIo\n" +
                "182199sp8LhA0IK1kOktpKdDwpVdwavDHmVwEdEBSaz9JL7kRUHZ7ui+Z9Ka/gi+\n" +
                "/RyBOqMfVrugxdru0CthfGAtap7OpADZcbactgL6/F+jMgHhGQDkSY8fe3Dg+JvR\n" +
                "BLW42PItCICC1LvD45w7oVHVgnQlgYfJhxf6ZKKqy5oHeOtpX6FMqs7TZ1+6V+qV\n" +
                "9wGpYNk812vN8AykTv8MO6iTOoafhfTSDB8vuxSBA6ilQ8BXOzgf7iBGUedKAiDo\n" +
                "Xf9GhVMsdvLU83Eogg==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(requireExplicitPolicy2CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(requireExplicitPolicy2SelfIssuedCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(requireExplicitPolicy2subCACert).getOrThrow()
        val selfIssuedSubCa = X509Certificate.decodeFromPem(requireExplicitPolicy2SelfIssuedsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, selfIssuedSubCa, subCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }
})