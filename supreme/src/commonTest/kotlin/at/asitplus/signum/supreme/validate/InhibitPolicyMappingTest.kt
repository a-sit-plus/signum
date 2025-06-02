package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificatePolicyException
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

/*
* PKITS 4.11 Inhibit Policy Mappings
* */
open class InhibitPolicyMappingTest : FreeSpec ({

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


    val inhibitPolicyMapping1P12CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDtTCCAp2gAwIBAgIBODANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowVTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExJTAjBgNVBAMT\n" +
            "HGluaGliaXRQb2xpY3lNYXBwaW5nMSBQMTIgQ0EwggEiMA0GCSqGSIb3DQEBAQUA\n" +
            "A4IBDwAwggEKAoIBAQD1I5zxceMZorGyjg1wIoa8bfGeT1qfHYrEVfYDrHwug5k4\n" +
            "S1cwzlE+S2+1a4izALDGq9AwRgmnu3e+sD0D+D0jN2dKQN9xChH+u/IAI5Mtbw7h\n" +
            "ds2yHU90cqNFbkEk5JyvBdGLvJZ4BVc/VuJaxdDIh3xUADnpk2wXjPGJSol4Sjdc\n" +
            "pb7m4/YaDl0dAc+r3r5U1Wz5BNqI0A3JvezPJxTYnBQN0JvEkuSOg0TfmAUFqEqB\n" +
            "o/mCz1/h9Lycz0qwqOWgyVQvvfIpD5YtZF1Bek9JISleu2pEaiRkulVCK9TP26Wh\n" +
            "ZSE/vJAhnbX52Unpz/Kp3jlUwU/DDbM7KW9bRCgNAgMBAAGjgZ8wgZwwHwYDVR0j\n" +
            "BBgwFoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFE1nfo3dORmv6Cbe\n" +
            "DgE0eLF1ENqkMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MBIGA1Ud\n" +
            "JAEB/wQIMAaAAQCBAQEwJQYDVR0gBB4wHDAMBgpghkgBZQMCATABMAwGCmCGSAFl\n" +
            "AwIBMAIwDQYJKoZIhvcNAQELBQADggEBACsyNZjgHZskZHR1CLfKK/Ny/xYRo8ln\n" +
            "NaSzPGFEcmltgkUFAEKmjnzITOIg1kyPeOh9BVLbtjzuXVJ83+2Y1MBzqDTmrGFg\n" +
            "F62PRAXKkH54QyT00xP0TbmMQ7DEIRAf4Dam+mT8tezBbJgr9zjSTQdh2R0JxeI9\n" +
            "J4GgBMuASTMF7NDDtl72adRo9xzJu9FFucSKUsTkYjm2muUStfZH0ULJoDEm0MlJ\n" +
            "CEZWukj49JOznvVgWtUaHv50/oRB2Cgl94NIcs9lAsctA/cw4i2pQhede94SUjFK\n" +
            "pa5ZeQWQ8rV9MpXFEZ9qRhekJ+ckfqSvPWUcZIW4wve16E/hR83Fre4=\n" +
            "-----END CERTIFICATE-----"

    val inhibitPolicyMapping1P12subCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID9jCCAt6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTElMCMGA1UEAxMcaW5oaWJp\n" +
            "dFBvbGljeU1hcHBpbmcxIFAxMiBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEw\n" +
            "ODMwMDBaMFgxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRl\n" +
            "cyAyMDExMSgwJgYDVQQDEx9pbmhpYml0UG9saWN5TWFwcGluZzEgUDEyIHN1YkNB\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/QrlXBwBH0gps8hquY5\n" +
            "TPS3Pl3nIpIi+sth4IelwQSoZHaegDK1qWdnTQjv/lJ596J3TXGnzqNuvGddznYj\n" +
            "/GR71RLDV78euoXdw2VKFfE6UwC8R7qPvA+1VmkGwY4t93AvlWMvZNoevz9bnWvC\n" +
            "coByRgFDino7JTHz9rqxeAumf1hU4XnwMXqbr/am/INJrbGSLqWFawaF2YZwnvCb\n" +
            "4/ykemKyYf7CSaQ85WsuAMwUU2UdSVqsW2n4ATqYQWs1KUOOYFMVVHBZu4v44Q4L\n" +
            "BYk8fBa15ly4LoiJeqjKpttt8oyNktCEhxN/j+5zHKgIVYKYzd0lz6u0isRrifee\n" +
            "bQIDAQABo4HNMIHKMB8GA1UdIwQYMBaAFE1nfo3dORmv6CbeDgE0eLF1ENqkMB0G\n" +
            "A1UdDgQWBBSqJpQdZA9+BbxdYI0HV/xwlWZs5zAOBgNVHQ8BAf8EBAMCAQYwDwYD\n" +
            "VR0TAQH/BAUwAwEB/zAlBgNVHSAEHjAcMAwGCmCGSAFlAwIBMAEwDAYKYIZIAWUD\n" +
            "AgEwAjBABgNVHSEBAf8ENjA0MBgGCmCGSAFlAwIBMAEGCmCGSAFlAwIBMAMwGAYK\n" +
            "YIZIAWUDAgEwAgYKYIZIAWUDAgEwBDANBgkqhkiG9w0BAQsFAAOCAQEAaYLtBvHj\n" +
            "nfmFJ0JXZk9449d+fjF+N+jz0xgBn+8jeIDUJwYd1KBIjhMd3/ILnnRWwt8pNwXF\n" +
            "HeBs7GEoFuqFmycVd+aP+1KO6noitwU2os8h1yFzvTgJYN/MUaTYUqQRiwYIy3Ol\n" +
            "ZXQhYHCf1+7qjfNkQ3yqY9YCh3rRDMliVtfACkV844ijTOyUXP/RXvpYkIzMW0jb\n" +
            "rFtIo5pJ68EfpJV4DA6yA9raBAyuxTXxStnkfzwte4pTwXivLzp/5mDe+myBXAzv\n" +
            "7WThsPpxuc4yL+KItZPS7HebwOSqDRuOMyGi5Cqn7zquvphTfi/poJQimamBCrfS\n" +
            "DJ62v3/CviEAZA==\n" +
            "-----END CERTIFICATE-----"

    val inhibitPolicyMapping1P12subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4jCCAsqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEoMCYGA1UEAxMfaW5oaWJp\n" +
            "dFBvbGljeU1hcHBpbmcxIFAxMiBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEy\n" +
            "MzEwODMwMDBaMFsxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmlj\n" +
            "YXRlcyAyMDExMSswKQYDVQQDEyJpbmhpYml0UG9saWN5TWFwcGluZzEgUDEyIHN1\n" +
            "YnN1YkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA41RBZsVSZtw5\n" +
            "b13HlMhvwmwd6KG/vDnbeZnxFMOvUE8T75Dz/1P0SCSkix1T+G1FdanOupx+Nv2X\n" +
            "+qo0xHV/tdme0V1AEbx3Rbt4fFJM8OZed/YpoRiHrl/yojesRZv0hk0GO4lOBgxH\n" +
            "ouKj0vXbTIOFj/3oD1q89GVUpkShTUMRQzL64NKhqiPP2hkQIP0O3heR89nqggM1\n" +
            "/1oyC9Eu3ShvcUtdNLD1MVdPxIQJ3ytC9x6i5wFJVyFF/H7YuREKDzeXt4Tb0ESr\n" +
            "Lq79pDFTOiU64au28ClxKNgOZMTn+vKKuKdxOdqkbQn8jQyws1YjPPoilWxoC0aB\n" +
            "Ev32rnqHXQIDAQABo4GzMIGwMB8GA1UdIwQYMBaAFKomlB1kD34FvF1gjQdX/HCV\n" +
            "ZmznMB0GA1UdDgQWBBTXgFwTi45BdroKtXNx6KNAgHQO0TAOBgNVHQ8BAf8EBAMC\n" +
            "AQYwDwYDVR0TAQH/BAUwAwEB/zAlBgNVHSAEHjAcMAwGCmCGSAFlAwIBMAMwDAYK\n" +
            "YIZIAWUDAgEwBDAmBgNVHSEBAf8EHDAaMBgGCmCGSAFlAwIBMAMGCmCGSAFlAwIB\n" +
            "MAUwDQYJKoZIhvcNAQELBQADggEBAFMmz8KB5cr40DimQ006k+qjMH3kjROwVMfG\n" +
            "CFQ6dBQawNlZDTw+1QTFc8AYH7kBFGY0UpjFZOVBcraW+FmVFEekGN7a4EQ9Gqxf\n" +
            "/+xgUSbQF4PpH6G7jqCPPJhmZX7i1ByEx0/FD++2QAd6aOETOGshp5o7dy5SHSvC\n" +
            "BWwmb6XTcP1+gJggvVdQFpRSdt6l+7+3YveSOhhfw+z+LvLWwjqAhuBdvvON9qqc\n" +
            "uWTkj7U1wszl5QqbPJcbvDRLEkIccnDnVDBRm8rY5lN5S8G2nODVQXG+58/0nytL\n" +
            "6yiE26xchmmFEWVzIwWfCUbBtOM4bYtGgj2Os3O8RRBzNprZEtE=\n" +
            "-----END CERTIFICATE-----"

    val inhibitPolicyMapping1P1CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDpjCCAo6gAwIBAgIBOjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowVDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExJDAiBgNVBAMT\n" +
            "G2luaGliaXRQb2xpY3lNYXBwaW5nMSBQMSBDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggEPADCCAQoCggEBANNzchiVXFu3PN6VHXl37Lfl6CWd/nzabFywiheAyXJQhKpR\n" +
            "ijrhHUNfWUFZpy0s9LcXQCibTwAXHTvNm7bEsIxP7bZzBIxyJXkrNMO/OAm1xGo9\n" +
            "JeMfADrtJWXuLzLyLs4OZsmcjMConJwClu5OoHRu5PzFM5UPg+dLdl8P832Ug9ol\n" +
            "Cmp+R1Dh2euZgbuiLkdLNdy8COfNFYDHAm8GoqueauaPUMWMH4G4GVTkKsvB6zoB\n" +
            "yV5HN37kek/vaLbtm3RjCu4Wp5/kmjbHMZZqq3/8m8FGZykna9s3vVEcTPDS1A5h\n" +
            "hkzKi7qaqirbvBFzU8LLtf8kgSGo+aABvGTU3OECAwEAAaOBkTCBjjAfBgNVHSME\n" +
            "GDAWgBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQUvradvSl/GqHZi+Gk\n" +
            "gGiDKK1K8AEwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEw\n" +
            "ATAPBgNVHRMBAf8EBTADAQH/MBIGA1UdJAEB/wQIMAaAAQCBAQEwDQYJKoZIhvcN\n" +
            "AQELBQADggEBABSJW2Z9XMCKoB6BKyAvE0tkrFt8XNnIHpUZDJPUKA75KgTSXXk0\n" +
            "Z+/4YjCsbY3N4V2vYWIBRbQDzVt+ux0E/flUUiD7cXdutJ9/EJgzZurplxbtwX6A\n" +
            "dauSywWwlpMrk/l60ICN3yTfQSauljnrsTcKe9TqYptyGgSxxrEPXXvQ/gx8mKhI\n" +
            "Y3PERCuZb2WYzbYQ8cyJe7Q3HYLFuEWgTN6g2ZfCRcu4XMBsmu8sT6rNL0U4OOU6\n" +
            "ZFXZC0EejThj5NvNPYzmn1ROfgZvPYrNAHJjQXcCaMBN6odbLkAKYmGaKRMkCUPQ\n" +
            "BS+EhzDfuGxj2JFbH5mkVGfpoLeXvS34kfM=\n" +
            "-----END CERTIFICATE-----"

    val inhibitPolicyMapping1P1SelfIssuedCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDnzCCAoegAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbaW5oaWJp\n" +
            "dFBvbGljeU1hcHBpbmcxIFAxIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
            "MzAwMFowVDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
            "IDIwMTExJDAiBgNVBAMTG2luaGliaXRQb2xpY3lNYXBwaW5nMSBQMSBDQTCCASIw\n" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL4hFAK6xYrGnE8mqLy4jasyD6TX\n" +
            "qUwILdx9MxRmFng2VFoARl8eHjGWt48XdOqiGyALQ68aW6WIk+AZV4YAFWXlSdBy\n" +
            "QWTCTE0tM0b2kJmxNIqbzNMBdzRcP4yPHaLXSPt3AYZgeHuG/zGBDSiCsOwXZiFB\n" +
            "sl0o8u5wTeqzpSMEPa5Zs0cN4f77npYpcOsAo3r5WezL6r/nx+oj6BaA/qI/M90Q\n" +
            "xGzA0RkG9p7uJUjemkx1g7aQaUMvsnXDyXOdpzAslQBy191evT+sQ4D5pabR8yFq\n" +
            "vtIfkeQItwj49zXso9CZppXohWRC/HlNw98aq1bcVWhMwLkm28lR9Fn+KesCAwEA\n" +
            "AaN8MHowHwYDVR0jBBgwFoAUvradvSl/GqHZi+GkgGiDKK1K8AEwHQYDVR0OBBYE\n" +
            "FJfMQl7X+BVEi7OXUZLdbAE7IRjYMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAO\n" +
            "MAwGCmCGSAFlAwIBMAEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n" +
            "AQEAKPe/EX44EHfBWAevfNDVzkd1uf4IuCyftrKHY18e+ikOZOw8KXzz4SzcHus9\n" +
            "d/TB0z9iPL04fREfVICqExRqoH0rcMxxJ8td4eohoEKVeUc/1WrnH8KvdeOTj1vW\n" +
            "npG3Fm3M0FHoLZFWQpbFKEUowu5FY5GgGPnnudUzxCP2A+6oXxDAhFVkzZVAailF\n" +
            "tDrPT0BSk9O1/v5DCmfVsAlFYwzXRzddRmjiiLh5Tb6Acd2uJgi1bjQCYiNbZx5E\n" +
            "gcgDjHuYzL2JBihShFLtFzdz9OtyRwOrsgMvuKR1erW7G9OvXjDpLfXXnFsXeH5r\n" +
            "5D3Y/TMQa7VJlW08+WlEYc0wcg==\n" +
            "-----END CERTIFICATE-----"

    val inhibitPolicyMapping1P1subCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDzDCCArSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbaW5oaWJp\n" +
            "dFBvbGljeU1hcHBpbmcxIFAxIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
            "MzAwMFowVzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
            "IDIwMTExJzAlBgNVBAMTHmluaGliaXRQb2xpY3lNYXBwaW5nMSBQMSBzdWJDQTCC\n" +
            "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO2x9/hMwh7GCDcxZx8y0j/4\n" +
            "Ls1Qow36ywaMPWliQ8ql4neUmZciT5WfoY2u27nmkFA5HiBDGt8NMEd1dJAaEHFn\n" +
            "luDroslPlbh+1dEhl744TWroaGCXETaFHFNY3jPzo3XVU/Q+Yiy2ftK0ZzSVaHz3\n" +
            "Oqv52scuXm5hgFHSrt39qoJXGErlZ9S+x7t2fFnfAeO6q7evYgJQsF7yJdbNQCfs\n" +
            "YnBfz2vFvnPwIXGEmf8aNrO7qgcPg1J7AlKZ6+3pYEL4bLuwUmtxcZyfT5kKKxbD\n" +
            "Gwg/iHov9K/5X28xnuBHpTmuRWVoDgB3kgBxLF/ZxXXO9Y1Iv6k+e3uAsZpVLfEC\n" +
            "AwEAAaOBpTCBojAfBgNVHSMEGDAWgBSXzEJe1/gVRIuzl1GS3WwBOyEY2DAdBgNV\n" +
            "HQ4EFgQU880HP4Mw08cCYtrmymwBpbG2gMswDgYDVR0PAQH/BAQDAgEGMBcGA1Ud\n" +
            "IAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MCYGA1UdIQEB/wQc\n" +
            "MBowGAYKYIZIAWUDAgEwAQYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
            "WYy0yUE7kUeVqhHdNJdc55+y5LP9BKcz/sa8l3aqo7RjKOmj2cygt9B7E4DRJT2S\n" +
            "uot9Gp/rHVPv0cknQ/3SDBwYtHCSKV3bB4eQp5nCiMpWaAWXamUTNqpY9qEOJImA\n" +
            "Ctg7bNL/t46eGOWhixz1wUMDMGGkS+rIzf+UJqHOBAUdkEjP8ouUWBTlNsQrwFxc\n" +
            "x1u1GiuxWPzIAIjOV1xtUPSLig7Sv5uQccmf0vHh2KkMtO+1dCoTbV30QLWvbVwz\n" +
            "wzi1DzPMvAWqTVXwFQrYev5mUh4XJ7wMXHp5WW49qmdamQeIKImxzIsgHaVlKl2K\n" +
            "eFX6REWaJ3Sv+U7KJ1eaqw==\n" +
            "-----END CERTIFICATE-----"

    val inhibitPolicyMapping1P1subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID0jCCArqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEnMCUGA1UEAxMeaW5oaWJp\n" +
            "dFBvbGljeU1hcHBpbmcxIFAxIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIz\n" +
            "MTA4MzAwMFowWjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNh\n" +
            "dGVzIDIwMTExKjAoBgNVBAMTIWluaGliaXRQb2xpY3lNYXBwaW5nMSBQMSBzdWJz\n" +
            "dWJDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJJrQ5z0bfU+HR+h\n" +
            "7+Rok9J7y4aPRd50OEgl+SGnwBLodQ1xgyZUhJgSbIeaLCw5uYUWJedxh1TQM4Fg\n" +
            "RZD5VIMFpFjIu4xg0mRXm+YomjBkF2eGCtpgjRjbO9rbjVxj01oQmtE+595P4OFb\n" +
            "zXKXkb9ilbFvz2zVKJ+1aTENKJd9jB9STsNz5NTKVRUSr6WF+gn8HJofrpsQdZVO\n" +
            "qQOk6GAB4FK1/0TyNmywGXWkEbM1WJeejSnHuNX1gBRjlCorwOKP5M/T5mT1KZUP\n" +
            "x4Fhk826XPKMxGvC4xKNfpjlmgHGH7LpsSbLv+4UE0aGVPcKbkwx9b7W5Ot5x2c9\n" +
            "urn9WnsCAwEAAaOBpTCBojAfBgNVHSMEGDAWgBTzzQc/gzDTxwJi2ubKbAGlsbaA\n" +
            "yzAdBgNVHQ4EFgQUPkV0oovS8VaMRgFmeHAkxiLBA54wDgYDVR0PAQH/BAQDAgEG\n" +
            "MA8GA1UdEwEB/wQFMAMBAf8wFwYDVR0gBBAwDjAMBgpghkgBZQMCATACMCYGA1Ud\n" +
            "IQEB/wQcMBowGAYKYIZIAWUDAgEwAgYKYIZIAWUDAgEwAzANBgkqhkiG9w0BAQsF\n" +
            "AAOCAQEAdfivFridTE3XIZBYeomP2Heqj4tX3TiDbCSCOiIs/608QnZS7a0e1/yl\n" +
            "yPWexV2WMAOv9HvdaQ3HtejZpBPvc0Gmu1M45vCdjQC/4/MWbtKVl3buBecRcWZi\n" +
            "z9sfajKhlZzXISyOp9GjWfH6OYtPypj1xMvqIj4NSEu+RWyavJzcVIZtVWiUBGQc\n" +
            "zR3jxgTs6CzWMbXFe/dHrDzdBbtLk6Z647Co19Cg07I4OP21gQB7nombxlv/EHbb\n" +
            "BajVkd+APg6NNDCV+JgSU3XXQpTGiSx0J6P+39FrRPfTJcdUIIfSUoxuTDVy4Uzj\n" +
            "+66fxMiAaaII4phA6fBlCj2mWvBr/g==\n" +
            "-----END CERTIFICATE-----"

    val inhibitPolicyMapping1P1SelfIssuedsubCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDzzCCAregAwIBAgIBAzANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEnMCUGA1UEAxMeaW5oaWJp\n" +
            "dFBvbGljeU1hcHBpbmcxIFAxIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIz\n" +
            "MTA4MzAwMFowVzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNh\n" +
            "dGVzIDIwMTExJzAlBgNVBAMTHmluaGliaXRQb2xpY3lNYXBwaW5nMSBQMSBzdWJD\n" +
            "QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKu1zv/j9hUO9KsCMtIO\n" +
            "6fmdTyGxvmTo1iBnDYkOMkunYTqq5hxL6QRQbAdpgTYLDF6TpPEl8WwYd4icjMH2\n" +
            "jv/Ddrf1U4ep7S3cHeXJv0i40BR8f+UOGHv9XCQCZPWV9Czw3tlLsDBPq6epG1Mx\n" +
            "U+/LOdd74z79dTHmNqCKLjO6fGogYqSin2H34OVAABxTSjdoWYFe+myN0RDgsO4v\n" +
            "y8UZb+ciM1aPw4Q0pkPI1tBkJVQlFdVbVawrOkzSLUisQtfbJObFMTwKaFS2JYr0\n" +
            "GWbBBhH1IS4dVh4vktIQLNMCpjkTLvoFVO9KH9VKnZzW4UrBcvqbW7zrkKfr2eD4\n" +
            "pB0CAwEAAaOBpTCBojAfBgNVHSMEGDAWgBTzzQc/gzDTxwJi2ubKbAGlsbaAyzAd\n" +
            "BgNVHQ4EFgQUWblsZOrzrpbqtlFcJY87z+31kw4wDgYDVR0PAQH/BAQDAgEGMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wFwYDVR0gBBAwDjAMBgpghkgBZQMCATACMCYGA1UdIQEB\n" +
            "/wQcMBowGAYKYIZIAWUDAgEwAgYKYIZIAWUDAgEwAzANBgkqhkiG9w0BAQsFAAOC\n" +
            "AQEATJR8hHpUS/Em9JJ75jdfOIOlmBAgjtQjqMjH0rZm/h/X0whS/3ElXS9qS/3s\n" +
            "OuhFKeYAaSa+2nvKvqHVmeHRSAOAKZHz5AZ7vCSikh+KR2FxMp5WM2cqrwj7q+cq\n" +
            "d6fHaRrSbZfPQDMu/rBm6j2wYLb3RvzuuMFpEkSgbbqSNFVAmZrLfBsP20yy8NLz\n" +
            "HXwInqwU4lI/02ekuywzm+ZRdvDPQWt7RxomC8KWHR94tCsFtltZsM6r+20WKD94\n" +
            "7+XJP6fp8KeLFQkDlSI3EEaBGjVJwGFrrJ3GH0AkB2u9iw0+G1IwGdTwn4P7tu8L\n" +
            "UYwi7y/iSXXcEQaIQAdXEPHVnw==\n" +
            "-----END CERTIFICATE-----"

    "Invalid inhibitPolicyMapping Test1" {
        val inhibitPolicyMapping0CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDozCCAougAwIBAgIBNzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUTELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExITAfBgNVBAMT\n" +
                "GGluaGliaXRQb2xpY3lNYXBwaW5nMCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                "ADCCAQoCggEBANt7nMME0N3fefF9kFthzAI8C4Y0Ul3e4aGamPxfGzSoKVgKIEXl\n" +
                "yKbwGaBplcjaOjQxl6MO74pTzEcOUDHshkf1uLJh8K52pJDew36C3KrZ3cMACKrz\n" +
                "LgvwigxcHTWFv7Rey0n76TupvA8HGAl663ah2QIt8I1rCqmp/7raxqQxbBJFC2Ti\n" +
                "pJ8XZrHzIPnzkP/RjVgHH+2vgxypQh+/Izw9E9MOLnkXKUUE5x6rCHvbz2CHJ3L2\n" +
                "QXlqaZJz7hqKIFASnaY3FPKwP+cU/bmIIImXCTjzYx5hiT0rixD/bUb+pXkcZkF5\n" +
                "WTZZ0MU4VyLYTAEnBeiiX288aaDV4vUli/MCAwEAAaOBkTCBjjAfBgNVHSMEGDAW\n" +
                "gBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQUWDcmB5GEYKzu9kA+pSv8\n" +
                "/5cdndswDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAP\n" +
                "BgNVHRMBAf8EBTADAQH/MBIGA1UdJAEB/wQIMAaAAQCBAQAwDQYJKoZIhvcNAQEL\n" +
                "BQADggEBAFzEkzKG6Ig8FbZ5qGL/3Ua5qibD6Ky88jtku7s2ZG6vQ/GC/5QAcWsW\n" +
                "Qtz7ajxzTqZ8ffXSFsmynLiUjmtPbpvuKmgZpklXi/8dWmy2DMxxBqObnOkASL0U\n" +
                "wbpv0hMTRNQZkYaNRKd3G0mSJdLCR1ZumDQfxYtSSB5I700rLZNqxLgF+XemTNqK\n" +
                "NQxcVvAFOjJ3fu6a1lRPr1ahvyPgPfUGugETMoMQ95cqM0Aj5Zo0ZRUQsXS0XCtV\n" +
                "D5ZD4THlPWdUcUKaF1H2vVvidJX8dGV5eA1GkJ3VFb2yAmbEHxgzfr6YgD4jjgAc\n" +
                "ksRGDC7jO4eEsZYanmTqnXdR7xBFN6w=\n" +
                "-----END CERTIFICATE-----"

        val inhibitPolicyMapping0subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDxjCCAq6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcwIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowVDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExJDAiBgNVBAMTG2luaGliaXRQb2xpY3lNYXBwaW5nMCBzdWJDQTCCASIwDQYJ\n" +
                "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOxx/fK0GiaWvaebSvC+tR/65oOxtOB0\n" +
                "i2rlCHg++AGW0iPfXroJpby/vqElvVGZ9/L4ZC4ESfkKlcP99E5jqxNFqxNmjXbp\n" +
                "ySBDusJ7cGIK+Qqd2tkfXPkE0Ov/XqQYa2hXqvZGbwPyXTjkjtaL7k/xJ42vJ4vY\n" +
                "VyB3TKHWnm7VK307P6R74SvlLeTqcbNY8UtjZ7y88mfufWAKczbDq+0BCMpjFaUz\n" +
                "h2gJbp7XZXrsDq3NdQ6KSsiU4YKDk2JKtPZuLxlHXl3DELKzcdTuipGtbxvTheOB\n" +
                "VUfJKo24hBDWSry7ejCKwNbxMwXGovRY9FH8iHNKjEefc7W5d443rQUCAwEAAaOB\n" +
                "pTCBojAfBgNVHSMEGDAWgBRYNyYHkYRgrO72QD6lK/z/lx2d2zAdBgNVHQ4EFgQU\n" +
                "/7RzYlKNXJY6WpCuGry4PHmBYx4wDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4w\n" +
                "DAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MCYGA1UdIQEB/wQcMBowGAYK\n" +
                "YIZIAWUDAgEwAQYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsFAAOCAQEAvmTHRMpF\n" +
                "Xgn5rrscWjGbzojCzy8p6s2fH1D02ULqEJtJXFbs/UIVByZaMU+s9g1yRz6NsrBY\n" +
                "YJeUKc0l4OZeOmM6rHeXVD3KUBTb1dvZbc22Y4LzzRacv8p6XF+jtiTI7hnkv+7I\n" +
                "AmK1y9IOIMWB0mKT/uRwzFn5GG8kYyIQuLGt/xB446nHL5M0k6kstz/aApkA5A62\n" +
                "LUZs83AcF/p+NK2bY2rGFrbfoRtxFyOKrf8bwc1GmHdj/KeQT3iwJo9ilYOECY+0\n" +
                "DmL8SbReR2oE6KM3Y2FTcVu2aBh2kqiFRU/DUu3Qso9hQ69920KdysFj2I4mTRWB\n" +
                "Sn0cA3GqJO54Wg==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDsjCCApqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcwIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowajELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExOjA4BgNVBAMTMUludmFsaWQgaW5oaWJpdFBvbGljeU1hcHBpbmcgRUUg\n" +
                "Q2VydGlmaWNhdGUgVGVzdDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQDN0IaRs5W2GuI+RQoATLnfq2uut62sjrBHpXm+/0DkgNuM/dfoGsYDLwBKfGn3\n" +
                "qgoAo6ji6khYrCtR/+SKIurS8zuH+I/cYeiRZ12Ibg/Ua8/xKRbh/7nd/80SBDiA\n" +
                "9CxbInnuiP+oHXSLf40ITa8aFCfrlPah71XFk5J7LBWKrGgNmQoA23m0tP1R8QWS\n" +
                "OvvlxEVeQGazDd/2gQlr5t/cmbvzGTS7beiHjq+guzeoaERJ1oYldpvk9hYf2IsG\n" +
                "+MaVIyNLj935jopLVkAG5Zt1zVfYeSgm8Rxba3+S2OcCmHlAOM3XBUxBUVJN9WsC\n" +
                "PkLXw+Dk0SAGw8zDQXh9a6+NAgMBAAGjeTB3MB8GA1UdIwQYMBaAFP+0c2JSjVyW\n" +
                "OlqQrhq8uDx5gWMeMB0GA1UdDgQWBBRGnoIVM9ZVKmQsZhmhhwsQpoe8VTAOBgNV\n" +
                "HQ8BAf8EBAMCBPAwJQYDVR0gBB4wHDAMBgpghkgBZQMCATABMAwGCmCGSAFlAwIB\n" +
                "MAIwDQYJKoZIhvcNAQELBQADggEBAIYTbq4NLd0+LIfk3ppsdEzOz5LONFBc54w0\n" +
                "sh386ycVC5SBgXxibYDy0oN238lmZoAjvx6TWgAeVMP7TRwPyjMrOWivYWN2wBQy\n" +
                "8wE4g+Bo/NoLBzAHm9yaWUeILEG7xDm9Qpkj81Am/2jDJv4RTHkPqhC90Tbh/j9I\n" +
                "itkoVftRQlxsXx0NxJoSsfjDoG4+0LRM5elYHfBIldlHYLQiPcI4z4YW5FgtIs8m\n" +
                "WTAzVduck7L/ttW00UBYyWjek8HE6eDkTJFvHFfwOQ832M6inyBLrFiB0lD6w/qH\n" +
                "wekDTXqRelr/dtJvG0LpHq8/dEZeachaKBkm1oJoLKARAFkZWtE=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping0CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping0subCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid inhibitPolicyMapping Test2" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpjCCAo6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEoMCYGA1UEAxMfaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxMiBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEy\n" +
                "MzEwODMwMDBaMGgxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmlj\n" +
                "YXRlcyAyMDExMTgwNgYDVQQDEy9WYWxpZCBpbmhpYml0UG9saWN5TWFwcGluZyBF\n" +
                "RSBDZXJ0aWZpY2F0ZSBUZXN0MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBAPDRNocjMpqJS8XXEn2KeY/S7iXL8tNa1sS8X1umBKBSotfKudBZlQFXSesE\n" +
                "FC0og1Zs0syETNkUA1Wi+0cs+q2B0dNQS3oEzuMhMHRWjj56QtBiTFGwUs6qRliH\n" +
                "JJ+AAmcwOoMjsD64MFxOPtwAo71i1LAPbDXj9fZSPmQirI9ntOafT0RrZDVQwh0g\n" +
                "Sh6aCSAh/Bht8BgTaZW4MN/bi/cqv5v8bnFuV0BOgCE3O0frFuwinSG1d69ZOHHK\n" +
                "qVZ/fRfKNlxflSU0XcbtybYVgsyAoRL9Wq4m3RKsbtDeyqLa5SFTKRCMRw4ZCEIx\n" +
                "F1OMaeFh7etefe+7zDRW27l+2jkCAwEAAaNrMGkwHwYDVR0jBBgwFoAUqiaUHWQP\n" +
                "fgW8XWCNB1f8cJVmbOcwHQYDVR0OBBYEFP9zakNg0xu0uUYWu6rUrwVyxJTZMA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAMwDQYJKoZIhvcN\n" +
                "AQELBQADggEBADaelkwjWQrtrmyosROq1o2cNB2pldWpI3chT/c3cn8IpAQMMNHJ\n" +
                "Ch94idy6x/bzO7R2ZXlL5VCHPJlzDpClEOv8ZGebupN3+AE73Czaxqxrxj1xiOVl\n" +
                "g5imlIUt7oIjJibpLDVSH7Z2PcY9YK+/A6uaX1kll4oMtCLmoF8obFVp7alj0Hzp\n" +
                "uVpVfEq3I0dRLGLJCuOg0wCoyLtjV+YGp+uXXxYWBZc3CbxE1sVJ0g8D1JYLj5eq\n" +
                "uyj3Nmplo6T1c6i02z4LDtl81umgQyeH1JPijLH094G12i5L50QevtqQ6ifmFHjP\n" +
                "24mHZ/b0BatgDap0gy+JOYrPj0op5HrnU7A=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12subCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Invalid inhibitPolicyMapping Test3" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqzCCApOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTErMCkGA1UEAxMiaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxMiBzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0z\n" +
                "MDEyMzEwODMwMDBaMGoxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRp\n" +
                "ZmljYXRlcyAyMDExMTowOAYDVQQDEzFJbnZhbGlkIGluaGliaXRQb2xpY3lNYXBw\n" +
                "aW5nIEVFIENlcnRpZmljYXRlIFRlc3QzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEAv52QYQ1BWUErsri346fudEihcaQNINeU16WfsFvSYR/3ouv3u2Iu\n" +
                "kK9BngF3VahW7oyBeXwxmj/iAV2jimT/Fi1g2h639V3eHn8mOa5f9xzRbnUDk7vz\n" +
                "HqIx8UYup1zPcup4grk44BrkYyJoE3U4CRxDQB2Vw6lNV6osd+MuNyxkFZLnOie5\n" +
                "Hcl3UoXWG4lc5nCN5iNxxkaooKKlnOh4UR0Zd1jUh+AVP2zkzjw3OtER8PILl3fv\n" +
                "9hN/qcwW+0BSAemGQJDV5Nd7D5fCNJzbbXHToA3k/Bp3F3BqeE45IdFv4varhUjc\n" +
                "9pXAmno8Y9TXt6QAM5iN5UaJvOLTHkqqUwIDAQABo2swaTAfBgNVHSMEGDAWgBTX\n" +
                "gFwTi45BdroKtXNx6KNAgHQO0TAdBgNVHQ4EFgQUfdcKiPEJVz+3CWS6VMEBm+M5\n" +
                "jCIwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwBTANBgkq\n" +
                "hkiG9w0BAQsFAAOCAQEAVLVv3n3zSEYB7Pva607pG1mONfUdPsSkK+F+2SA3tSDW\n" +
                "v39v9BuFVejJ/WcJi8S9Oj7dB4F8GkbH/Mgjlr/SGWNC2gG5z1eG/Xa5ZsVYxT8M\n" +
                "o1XTK4S8TKdPPT2fvL3rHFwfsvhjama4zbB9/cG4HV0rRGOZIl2Dr4DwfdKxVllu\n" +
                "pF8syWwTfzNOPiwbBVGRVDqVapQ0s/qjMkwKYmVj0E+xcVphBmjG5f4KLzB3fTiL\n" +
                "YQHp6e/hD6fqDy34gnJKnvIdIpPS3mCJ32jUvs00gihBUXytvmF9mDmtx4D0gr/I\n" +
                "HW06yZ8bXGZay35h+u/+32Qi8rs6E5p9xZjqhk7yzA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12subsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid inhibitPolicyMapping Test4" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqTCCApGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTErMCkGA1UEAxMiaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxMiBzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0z\n" +
                "MDEyMzEwODMwMDBaMGgxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRp\n" +
                "ZmljYXRlcyAyMDExMTgwNgYDVQQDEy9WYWxpZCBpbmhpYml0UG9saWN5TWFwcGlu\n" +
                "ZyBFRSBDZXJ0aWZpY2F0ZSBUZXN0NDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
                "AQoCggEBAKYL62yu7+fSYzmj0n3w6uGjjzv62IQV/CL9BECVjokjFNxU+tfm3Mk7\n" +
                "Db7JxnHMEKR8jY4KvRmsaNSUe/3lK1VG4AFNzciYw4eDhOOLr5Kkx6EE3nbiWLiH\n" +
                "eE7CDRe68kwiRf71K4sUuRtHFKzYq78O1LY2fbYQoudnVbMs7JGj02nVqBA7M9iR\n" +
                "JKu6V6R/9EdSQEI7SFQEOJcnlIOkdL3Y5zYQLmXvoQ21RACpbPTrt4VFLQ9kUgdV\n" +
                "IwrIdD1qunbkbNTiaIjLcy8duhKBVx1m20MFY3h1uQc7SsOedEtCX/XA6a4GUZnA\n" +
                "TwBBiNePmhJUcN3P+35i8GBfin0K47kCAwEAAaNrMGkwHwYDVR0jBBgwFoAU14Bc\n" +
                "E4uOQXa6CrVzceijQIB0DtEwHQYDVR0OBBYEFHcvegxzhgIyUXHqaXOrOMLRpwmi\n" +
                "MA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAQwDQYJKoZI\n" +
                "hvcNAQELBQADggEBALkd6aOI5LOFb4xsYP6dSJe1DNfieEU6gmjHjphXiz1VXbau\n" +
                "0j1lqcxNj7GiOEThH6C9rgQ1DQmEt1DQrj4byYgnoMOa5fUwK5r3Mw+r+2SIGbyy\n" +
                "wvu6Sy1zdJ3OGymchuIfVXeaXgku/Uhf/68xSn8yw0HW9SEKe8ZDVZKTCXPPqnLW\n" +
                "FbD4xjBHXywSXlRlohLRuk9Rparq2Q18Qat4TOf/M1FjdxrToK+HRSfNw3e7cHQp\n" +
                "gxIvCK6mshrc9ojJ0aJRxvZEiM1W4/Twn8R+1sdWxKxeSfdz0Sl0jBHBVY/CqWKc\n" +
                "5Xh4d7lLxwItJ60kyVbsrsGeRJHtY1jyMQ9T+1U=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12subsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Invalid inhibitPolicyMapping Test5" {
        val inhibitPolicyMapping5CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDozCCAougAwIBAgIBOTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUTELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExITAfBgNVBAMT\n" +
                "GGluaGliaXRQb2xpY3lNYXBwaW5nNSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                "ADCCAQoCggEBANZnJDHPYGmDlhnjbX2Wd8iDOcwP3hJI6nYposXyUdQsXnA2DQ/c\n" +
                "hTL5jI1smsPgXdS1H+s53Ii5n5PoaaaXR3uRpgyf+T82oDL2NcWlUhvPwPee/Oba\n" +
                "mum7VeXYik1Itp3qDV5GJQlRLgpu8JN1Zx8v8CjvPUbgQxgcXpHh3tfSR+YEywzd\n" +
                "N+CbKRqflBhroXmwZQS0YMU+lF+qbfcVna0PoNjisg+LVT/uOvrskOVibfa746r4\n" +
                "HouY3g/mCBVJVb8+4YobezK7ixryFmUpiO1p9F8onRuB7a00ZBhtIHnT68+QU50v\n" +
                "iPWAzoBcsLPflYLR4BTClJ69xaFlNbGh+EcCAwEAAaOBkTCBjjAfBgNVHSMEGDAW\n" +
                "gBTkfV/RXJWGCCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQU24AHuWIsxcP980PiZlEl\n" +
                "u9v0HM0wDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAP\n" +
                "BgNVHRMBAf8EBTADAQH/MBIGA1UdJAEB/wQIMAaAAQCBAQUwDQYJKoZIhvcNAQEL\n" +
                "BQADggEBACAu1zkxR7sFDb4Yd7WMY2PuHviiAZVkYql/+rS9nTHFxSstRbaCaiUO\n" +
                "NhjeAVbZVGNqlbvW58W6OU+qXtv8+5U5rzJjAAMbLMklsrJnjyyntaxXZerbdh0P\n" +
                "RpIv4DP2mAmSCDH9qR6sJ43iHpvFO14CQNUofbfS1TYIw8u+NQGz3UwCfmMrQAqY\n" +
                "/teK8hMdEd7D1QUwRKBSi8icsPQiAdlVB7JCzSASaqIn/sB1nCwe/sYCAUdydfmO\n" +
                "AMQGyFymSavQq8WH9QnLn49/0yKnrJxgVexq2a56XDDiQnxPsVuXYr8uuNGPH5j+\n" +
                "XlwnsW2fsDoZawTjXr5DCStBmx0tnQI=\n" +
                "-----END CERTIFICATE-----"

        val inhibitPolicyMapping5subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDrzCCApegAwIBAgIBATANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmc1IENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowVDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExJDAiBgNVBAMTG2luaGliaXRQb2xpY3lNYXBwaW5nNSBzdWJDQTCCASIwDQYJ\n" +
                "KoZIhvcNAQEBBQADggEPADCCAQoCggEBALWNoV9OB/sGpzCATKUhLi110SMZVvGR\n" +
                "btEnF/hkxaUlmi0foAiK1RMgUSmdHLYhKLogfjVJZhvSLut+OECEtKZTYV2RkNVm\n" +
                "4igcfjs8aVhuo2z9lHZgqIkRpb/TPWkL6IgHVfLle352+zTscC6SVksC9J/o347y\n" +
                "WE46efxyYYSGqUg8eXqodBd9ReFqYUKMZG/6Zrk1YbSYWOkdhTLEbvtmgN1ZsRvZ\n" +
                "ImIZEAHaA2fKQKhwWeZax75qOeKRnzi0ZJCK4BFUkY5tviNclyNxbDCdOEyyrY74\n" +
                "5wTjSkImxYEArgn41i++i05U/Fo6c5BAtiEQJZwoOfFPUXZ6ri5kZ+sCAwEAAaOB\n" +
                "jjCBizAfBgNVHSMEGDAWgBTbgAe5YizFw/3zQ+JmUSW72/QczTAdBgNVHQ4EFgQU\n" +
                "2OxtvrdvyhNjyifMnFuiaTa28mgwDgYDVR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4w\n" +
                "DAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MA8GA1UdJAEB/wQFMAOBAQEw\n" +
                "DQYJKoZIhvcNAQELBQADggEBAEGWmRimtoryrWPMHFnL2kvI/vwMcVxQno5UzWGQ\n" +
                "FnqgqRgKpgNeeNJmzTugZVPWfK36cPehUYPAZJjtcUB2zBaEEoFghvtZgQPWR/M5\n" +
                "/amPSIHzt+mW3sXdJZ/lgkeA6nNanW/9AV3bWlYCfWgOdHiHym7hpKsk7UwHQYob\n" +
                "ynVgkL4oxSV+KglhXYGab20YiWNW6KPC0C9PCyu3PEG21WYsrFGNi5aOOlnTTW8z\n" +
                "A39i8vqZ023pgOkShxYBOvUdisg15xmSq+SzJZf5s1QyWd3kX5FRAsAOHWJzglvQ\n" +
                "yqeQX3fItsth1c7iJojcVhz8A0yuXICe1knhgg72TEqj/3Q=\n" +
                "-----END CERTIFICATE-----"

        val inhibitPolicyMapping5subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmc1IHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowVzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExJzAlBgNVBAMTHmluaGliaXRQb2xpY3lNYXBwaW5nNSBzdWJzdWJDQTCC\n" +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAORACl2TAi2vRGNZ0z25HHDq\n" +
                "63G0jwwUOBpMU1tGZM3EA6E6CZ1Od8tAsWfeW9sUj8K2m+t5ncmshD0xjUeLl9JV\n" +
                "CkJ7XsYI384YKQPdN96Wh+eNlbWRGi/DfmSiKwebVWOKVio7zMfv4rLdFEDYSUO2\n" +
                "62AJ9tOBc8lUEfqZiN+VD/AAfKXWfoyW2J8pJ0AhX77P9DAuzMiZKvE63yI0lodh\n" +
                "u9RKMVUPzLXq7FBY9xHexBFYGvGAtmuVfCfqNMR9Fu+loYqwb6KAAXnXh/DRq2TA\n" +
                "VveMGaMxuoCk4TPlkrraHiFitJgXnFuIsD19YQ1iyX28c6W3pfFjca1/MQUOAGsC\n" +
                "AwEAAaN8MHowHwYDVR0jBBgwFoAU2OxtvrdvyhNjyifMnFuiaTa28mgwHQYDVR0O\n" +
                "BBYEFDWn1OFLdE5VqHG0Qn8y/gQayQG4MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAE\n" +
                "EDAOMAwGCmCGSAFlAwIBMAEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEArfD53rmonDxsB7VLzP6pscDyvmqoQGKb8BgjxfuNC5AJflfBbbtlCeMP\n" +
                "cBIfFtyc0nECkfaO/tS6ZbzHyU7Oe69+jVOufQ0gdPJBITLCD3uhGXUgmTQdckXd\n" +
                "a2YU7ua8NZI040Vr7inevt8DjgBwfXEtUlObMCGO4OYtUBOXhQ9yW5KRkOBoYMks\n" +
                "PSwthYFiw92gkagk/jHwfB16VNIs9u/n0/848m4BzF7wNp7S5iG7yq/+fFT0WfoJ\n" +
                "rI/TZJTmIyWTJfhGwaV59ira0PrzzJuji4w62TpBAC/iKbeUqtLdRHBFgur8ccBK\n" +
                "VzdvksHDozhB+yWvQZNwqjIGoKb6Ow==\n" +
                "-----END CERTIFICATE-----"

        val inhibitPolicyMapping5subsubsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIID0jCCArqgAwIBAgIBATANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEnMCUGA1UEAxMeaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmc1IHN1YnN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIz\n" +
                "MTA4MzAwMFowWjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNh\n" +
                "dGVzIDIwMTExKjAoBgNVBAMTIWluaGliaXRQb2xpY3lNYXBwaW5nNSBzdWJzdWJz\n" +
                "dWJDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMOUe51QDDF4LIT8\n" +
                "dNI7U7D9/Co97Ayr2DWC3r1XLTRuFPRFy87WgdMLZKMwQFFyUlExeXtmH3k3hiBf\n" +
                "xQxkMe/RpmMzJsg2tR5ATvPvatP2yPAp9mdMCqn4KyWkMM7t7hKubm8n3V2FV+eZ\n" +
                "VCM6Q+wCrxjzLpx/BnALMkk/+tNg0mCF5xQoTi20AKZZVapwN/jUM8bEn4LDP9bg\n" +
                "jfvpZcP/J/IWRvQSRDBN7+62JT5DsnjJaXOD2a3ZgI/7shdoCOJJSBI1qJrSPkca\n" +
                "IwozCjheu1icHr+34/uLXkYFuIAs0my0IJx7y43RrWNA0JTJ/WNYB+humZHP30eR\n" +
                "bguXAbECAwEAAaOBpTCBojAfBgNVHSMEGDAWgBQ1p9ThS3ROVahxtEJ/Mv4EGskB\n" +
                "uDAdBgNVHQ4EFgQUrmPL1+LDceP0zm78NfSb0k0+3BcwDgYDVR0PAQH/BAQDAgEG\n" +
                "MBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8EBTADAQH/MCYGA1Ud\n" +
                "IQEB/wQcMBowGAYKYIZIAWUDAgEwAQYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsF\n" +
                "AAOCAQEAhxkEhZca1jstqu4SQv4NukDbw8Z3DdN15kwxZzgNfij8622UR4YqHu6/\n" +
                "dv+c0ANrgLR99MpRbvjimg4SnYj1Dlok4QJZN04jvvv0q6N3Tyvwf+S4LmaOyrXr\n" +
                "N542+uqYrOAS5UNAPF4ZxkT5L9OdxKQ5qqRNN5GxyxbPszvVA89/rFy3fHC+2OHz\n" +
                "eLgaSl/i0MIUhx+iCop1C+Svvt11DE3pBqRQly6A+MEtL9NjHVuJ/I6RxySHpbj2\n" +
                "46+yJv6k/OuWjVrAlhiDuUjwFHPVVnvHk1plcXLv77EnhxL8Yb2tNF7tM/0aG7s8\n" +
                "w5Idxl3AuA/XWMrmoLvQFlcYLm42Zg==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqjCCApKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEqMCgGA1UEAxMhaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmc1IHN1YnN1YnN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMw\n" +
                "MTIzMTA4MzAwMFowajELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlm\n" +
                "aWNhdGVzIDIwMTExOjA4BgNVBAMTMUludmFsaWQgaW5oaWJpdFBvbGljeU1hcHBp\n" +
                "bmcgRUUgQ2VydGlmaWNhdGUgVGVzdDUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
                "ggEKAoIBAQC0i3fp+XfZPUG9DSTq/8OqOa6mw5BfqUR2OVuxulyooJ4qHigWqHCk\n" +
                "muBd/ACPkowfECXCUCBypLRZ9hfDv+jZ+Jm5VWVMQ9N5qEkKae0BIxa7yv+r2r7Y\n" +
                "5zHMWK67D0qIh29nCdCJE9aH4q56ig/8oz5icRc5tA723KT7/nDHVBGIfr5EPkAI\n" +
                "/W2x1uNEwq85Qvy1bQdCUQkH4tbe0qLpYs013UQNFNH/NLuRQpDYFTMTyGApf34r\n" +
                "gNlFzcnwNtbDj8ewQITe4LWC0zw54McUtzmqdvSdSaawg91XyXg7bg6ecDoRCnPn\n" +
                "Ig/bCtm5RYKwPOIG5TMBFpn/vUtdUcyhAgMBAAGjazBpMB8GA1UdIwQYMBaAFK5j\n" +
                "y9fiw3Hj9M5u/DX0m9JNPtwXMB0GA1UdDgQWBBQMlU4t80WgAZvBvO7pkJDrW61R\n" +
                "nzAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATACMA0GCSqG\n" +
                "SIb3DQEBCwUAA4IBAQAubNdSsC6g4XBAAeavQ+94LbgE5Doy/MprXYSH7gGUDEDJ\n" +
                "aLUiqgOS4imF0gdBv2v4PQpsD3yALD4igMdIwO8M7wMSEwY2WyCNHa95KGmzvbSl\n" +
                "CcYjpPqXsrZOrZjYWF3JSSjIBEFVzWgSM5pGbtAnRD+wRXygTBGkUzKq9Rj6pFUs\n" +
                "FWs90SxaR0EBCc5vtNcpIQK5iXnYCO3rPHzcdcSN5Cr8VCrt5WvCrbxLFIoKr/Kz\n" +
                "KKoj1CbFqedcGBnRwwskfTLvEZdDs9xTr8I+A9DAZEoIPrcVB0rz9MH4biZBPDBg\n" +
                "GxCqwudDV9TUmuqh1Udp39odeV1CPWfTSzJz/gK2\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping5CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping5subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping5subsubCACert).getOrThrow()
        val subSubSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping5subsubsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubSubCa, subSubCa, subCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Invalid inhibitPolicyMapping Test6" {
        val inhibitPolicyMapping1P12subCAIPM5Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDyTCCArGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTElMCMGA1UEAxMcaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxMiBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEw\n" +
                "ODMwMDBaMFwxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRl\n" +
                "cyAyMDExMSwwKgYDVQQDEyNpbmhpYml0UG9saWN5TWFwcGluZzEgUDEyIHN1YkNB\n" +
                "SVBNNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0cg66AzOSJwdQr\n" +
                "Hj5jFNh8E1lyBSK6cIPyB102DVKLKmj4C4QpzcXk8/15iEOEVks/j397JUsyqlEp\n" +
                "ayfdGo1BNHq1oi/o0BfHcsybXcHmhRYieL3xUGcl4+9dNs2086nT5ZuOVR4grVlp\n" +
                "S429Rmdtny6k/mpAc/alvPmsgahUsSFFh8LoOgqPriVgFV/ifGBk9ig8CQwxccWB\n" +
                "JIvv8tFImPOxtaTE9a1bPV6hZbDzTIRxIz8c2FHtjPnI5eWsmhBpQ5/TFC+I7RJ+\n" +
                "2nJbgS9jo1J39J6Ll04WQVWREQ5nH/XwdmorkPJbURNL7XosTV9WaDhodZOkcPbk\n" +
                "Czvf0X8CAwEAAaOBnDCBmTAfBgNVHSMEGDAWgBRNZ36N3TkZr+gm3g4BNHixdRDa\n" +
                "pDAdBgNVHQ4EFgQUHQTPdicHjyI7wvSCLu7m3ROAe1MwDgYDVR0PAQH/BAQDAgEG\n" +
                "MA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0kAQH/BAUwA4EBBTAlBgNVHSAEHjAcMAwG\n" +
                "CmCGSAFlAwIBMAEwDAYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsFAAOCAQEAPh/d\n" +
                "V6FSzVZTO6s0ttZjFxM+5Yyi8gU+O74rUPUwoCo1zHQHS/ElM7nzk2SMUyW6/aoG\n" +
                "W3xNGijWrYMEBb/LosEjPbB9Hqct4pt6ahT0oE62FUI1J1LBkxa0CfCouLzoN/dr\n" +
                "SBLlsMtrYuDriGmr4GIF4MZAp0DgSFP9QcHuIWhfQRMJxNBmNT/nFbhJ6uxJiLoY\n" +
                "qaklau2l2aeEIa63d1PSwlVeyPYOdDFivB7i705e3mPL+har6GNQxpKVoeoljJv3\n" +
                "SJjAzw3TfDezPKALmsHtk7qD6O23r4+j8q/8cQqfB83/aL262oSN4Ov8vNvlHV1B\n" +
                "0BXgLEcrIP1K4LpS+w==\n" +
                "-----END CERTIFICATE-----"

        val inhibitPolicyMapping1P12subsubCAIPM5Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIID6jCCAtKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEsMCoGA1UEAxMjaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxMiBzdWJDQUlQTTUwHhcNMTAwMTAxMDgzMDAwWhcN\n" +
                "MzAxMjMxMDgzMDAwWjBfMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0\n" +
                "aWZpY2F0ZXMgMjAxMTEvMC0GA1UEAxMmaW5oaWJpdFBvbGljeU1hcHBpbmcxIFAx\n" +
                "MiBzdWJzdWJDQUlQTTUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDM\n" +
                "GmJ2x7yrfem6iySdHRgqYcT8hBb6YP7cMPaItRkU4vE1//h9uAPociee8y44Jb48\n" +
                "/sLrI+JP6fMT1HkxaKMix9R7PfZyh0wGB2QAfEHcpm9nMLuMamcHLi0O7Mk7vsml\n" +
                "Hxuc5mO9lt2XQ8f87NgZ8hpke8uCdGUvhydGR6q0GBfJd301D50GxUjbgxtuKAO4\n" +
                "KNF24bW/sXBGEFG/ryOVZjrdkKSMl20HCID7pj8Sc1rHPjX5o9ykRW1XlhsMvQIA\n" +
                "a4RzOh0BXm+zYKZbtJCtZrgCOEW6pdqEdoSU+ZybrE6jtn4Hl4FBLb68J+FjfiZa\n" +
                "pRXmT/r6vGKQGx7zVMFJAgMBAAGjgbMwgbAwHwYDVR0jBBgwFoAUHQTPdicHjyI7\n" +
                "wvSCLu7m3ROAe1MwHQYDVR0OBBYEFBKHGzVn8LyhoDa6FagpGe0am1twMA4GA1Ud\n" +
                "DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MCUGA1UdIAQeMBwwDAYKYIZIAWUD\n" +
                "AgEwATAMBgpghkgBZQMCATACMCYGA1UdIQEB/wQcMBowGAYKYIZIAWUDAgEwAQYK\n" +
                "YIZIAWUDAgEwAzANBgkqhkiG9w0BAQsFAAOCAQEAJEtvIEyehDWiKJvojD656dbF\n" +
                "3VkkvFiovYk9B0du4rrq1+fHr5KW5uhKO5G+0gnQAmb2s2DQMWDooC/w9UOzuagw\n" +
                "kD6Y2GswGG749QOEEOoYBcuU4AgmBQjp8jZ8b5WznQHKDlk0ZtBtO61Urmd5GJ3u\n" +
                "Nv690xew+zeYqXRWtR7Mjr+vOUU911TgfTF2zkUoY6UGw43qCz9krpJmoQ8Ky9Bt\n" +
                "cOYXgSHBOm3EtA+KMIo/mmmiu0zxhvBJTKWhAsRpejosqargDUpmbOzj8pw2tcJC\n" +
                "4K8mBvz6OFo0TEqoDx5LOZkBD4u8EGjSU3gc2Ou6RUL453iKyMN5ID0bRYFn/w==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDrzCCApegAwIBAgIBATANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEvMC0GA1UEAxMmaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxMiBzdWJzdWJDQUlQTTUwHhcNMTAwMTAxMDgzMDAw\n" +
                "WhcNMzAxMjMxMDgzMDAwWjBqMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBD\n" +
                "ZXJ0aWZpY2F0ZXMgMjAxMTE6MDgGA1UEAxMxSW52YWxpZCBpbmhpYml0UG9saWN5\n" +
                "TWFwcGluZyBFRSBDZXJ0aWZpY2F0ZSBUZXN0NjCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
                "ggEPADCCAQoCggEBANL0XE/6QZLLGmP45AS6Fok2FJ3qtjzy+nkJFlJ4QfdgvkLA\n" +
                "F/wf/aCbiX/p41LtukSbRGLWwVPfwN6uWZRvZcj4SOxhIRAgvWK4WrwNtgqVwGNE\n" +
                "3lt8AOJ83NFUArK+FANDH2rtzbY8igJOIEGQ0H1CPyYHM0g6O9gbACN6iABkxeoS\n" +
                "UrAFL6u+cjDFg7Huwt3C0DgZzZZk3zmi82K4RyfQnQ5n4sFHhJHCDviY3xQvW8u/\n" +
                "gC7o4LxeWrPJWSgn2jFUly771l+bg557D9CbR40HH37/JNf328clwHIFqwweU1gp\n" +
                "2MNz6/IobTvdSL9b0AgSUjbwpjCn1CtuN4p46t0CAwEAAaNrMGkwHwYDVR0jBBgw\n" +
                "FoAUEocbNWfwvKGgNroVqCkZ7RqbW3AwHQYDVR0OBBYEFJCTnO92Cq+5fy1mUiJ4\n" +
                "S7FH+7GqMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAMw\n" +
                "DQYJKoZIhvcNAQELBQADggEBAKWNC8GBMa/d2a5ls5LSN4BVRt0OK2AK41N0Ts/Q\n" +
                "A6D5aE29h4nScxZ20I7LB+8fMcuNyfT2rZFuBgZQ62Oqad+XsDsBFRj4NITol6M3\n" +
                "1OdW86Dezbc272tAukA2KqYAo/Z4j+/ag167leUKu5tf+5Cz/xrAx8/FbVZEXS3K\n" +
                "kyprlh/fy27UadewavhCgc88KTLF3DMnTPg15Ov/0SEtDZ46wdy7V4D7ao57Xe6Q\n" +
                "V2pPUHl6w5mvgCtscZkCqf0+AL3AUL81ks+wUghBnzCUBdn9Lsv/lfHYIUanRO7z\n" +
                "0VEto1h+4ot/XjDSG1nqJ3bTAJ++VB7pBJMGuiHeiEyhKQM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12subCAIPM5Cert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P12subsubCAIPM5Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid Self-Issued inhibitPolicyMapping Test7" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDsTCCApmgAwIBAgIBATANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEnMCUGA1UEAxMeaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIz\n" +
                "MTA4MzAwMFowdDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNh\n" +
                "dGVzIDIwMTExRDBCBgNVBAMTO1ZhbGlkIFNlbGYtSXNzdWVkIGluaGliaXRQb2xp\n" +
                "Y3lNYXBwaW5nIEVFIENlcnRpZmljYXRlIFRlc3Q3MIIBIjANBgkqhkiG9w0BAQEF\n" +
                "AAOCAQ8AMIIBCgKCAQEAzlSgxeR9mZZ2DfvlsNsMlfrKR1y6GJY4fciG6sC9DoRB\n" +
                "7sqa+3lG6pzDngc/9d/M9u85ukn4AMAsPZAgi5X6Q5dz9byxtr/ACLKumzRwWJ78\n" +
                "7vVSNc1Fl02DimJqpaVgKtpvh74Z0Li2EUONNxVmM86vcI6+K1qVnLMWtdrSpQx5\n" +
                "RcP0ak4XtVcxSFKBrTpZw7kplIenOiXBIVlO5f2yADWcpaJw299I0n++7v4vQrJt\n" +
                "3HWs5aDA4if8w5UsQvfWPL6IbYhS5spCRAu2Ta8TAB+mY2k/sLyYo/1HV0khIG1Q\n" +
                "5J1pFdw091TkMnOf0c+yG48BeXG230snsTTVpV8DKwIDAQABo2swaTAfBgNVHSME\n" +
                "GDAWgBTzzQc/gzDTxwJi2ubKbAGlsbaAyzAdBgNVHQ4EFgQULYSE/2xcGw+CRD5T\n" +
                "hkfTUDLk/bQwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEw\n" +
                "AjANBgkqhkiG9w0BAQsFAAOCAQEARKXDv0JsjAw+svbFFVLJWn3Fan9X4ilv2XPj\n" +
                "c25T2Z8dd5ydw+a/fSuZ30rowmL2YFnWeX9D3i+y542eBEQbzHkj+1oc/JFJ/34M\n" +
                "trqzj39TgmrQbM1D1SOb7Y2uLRXpZu2jPUuAld2jPJvFZxCHTf3LRb1dW8F6uAs2\n" +
                "SrfZdeFCA7fXoGJRO4z4cCWyROOQY2PHSrMKNAh2yWFq56qlj4iNmdv86/My8MNf\n" +
                "zlciq5ApLsPhTIZiRwuAiAnDkeVUjo0u1PciJ9oQUZc2TuEqcUudjtl16zTEw59Q\n" +
                "Qk9v21HXboMBS4QUaQ8WhtwL0sGOMNKSw13LgqFeW5IPswaGsA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1SelfIssuedCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1subCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Invalid Self-Issued inhibitPolicyMapping Test8" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDtjCCAp6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEqMCgGA1UEAxMhaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxIHN1YnN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMw\n" +
                "MTIzMTA4MzAwMFowdjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlm\n" +
                "aWNhdGVzIDIwMTExRjBEBgNVBAMTPUludmFsaWQgU2VsZi1Jc3N1ZWQgaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcgRUUgQ2VydGlmaWNhdGUgVGVzdDgwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQC21AXVGQebH8AHBIoewxwmy42xH3DuTS5GYC9g\n" +
                "FXijp4jeOhdLJCM2uAzHMM7Qib+uSYR0O/Cdz9NKQ/Np9gudh49XgtGMzflsjSM7\n" +
                "SgijS2qF97/TYv3wq8BkFjATs/PXJWo2S2VQuPce/yHzo63LO8ObEjnHcC1j4r5G\n" +
                "LY7718RgxXw6NeJDSXOxwJtFjPLMrXEFSVOiPh0vbew3EM1x9ieqJqVwcSaiBUpX\n" +
                "qIawbxJczfi2UqTuj9SVa7zuObF8qrDdhkdNUYOEFc2IzuVVIOskotPcAB4PwbDE\n" +
                "HFw02dcwdFrG5BUHhpdvIOmEy5IxQXwMyvsd0Phv/kwqNw/rAgMBAAGjazBpMB8G\n" +
                "A1UdIwQYMBaAFD5FdKKL0vFWjEYBZnhwJMYiwQOeMB0GA1UdDgQWBBSyFwdJn4xf\n" +
                "l/2lQPJVfyRDZWC6gTAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgB\n" +
                "ZQMCATADMA0GCSqGSIb3DQEBCwUAA4IBAQAY3dfWtAt0zVsSibvIAi3jQ4bHtVq6\n" +
                "jSo+i/7Cl2E2qevfmDrS/uUPwjjUXLOsJeiyFIPl/lB8yNC8KkT0oEe1PTr34gLw\n" +
                "9TTnLt3ZRdCbKqg2WRMv9Y1PsBgWTRcYED+/0U8UQxePr2pyHDetdpJuT+phwvRc\n" +
                "2GvvJ10UjVJvRCVw521PuHwDyF8JBmpsJQSPOe/L+jnLWOehAxHOeI7CMaqsddpq\n" +
                "JEq6LZ5ofOV7JaFJMxYscuj9mLRKcXTAnnWUp/9PzrUGI6wr1WG5OdECNwQHqO9s\n" +
                "uxeEelksAhiqK4Yg1BFJeppQvyfKwd/Njw7ohwTYBcsfojiSLl2a//HO\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1SelfIssuedCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1subsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Invalid Self-Issued inhibitPolicyMapping Test9" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDtjCCAp6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEqMCgGA1UEAxMhaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxIHN1YnN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMw\n" +
                "MTIzMTA4MzAwMFowdjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlm\n" +
                "aWNhdGVzIDIwMTExRjBEBgNVBAMTPUludmFsaWQgU2VsZi1Jc3N1ZWQgaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcgRUUgQ2VydGlmaWNhdGUgVGVzdDkwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQDh7DaIU7QitpglwGQwVBh4gziggxUNZYv4N9CF\n" +
                "ua9cMz1wtL8igEcrkH3bS7ExC4XDquZH5UQpQ/rrMvW5McM8DB8yoHcDq6PdTHts\n" +
                "swQ/IhF9IxGcHYlC6xXf2IDFk/QVa6PGEa8a+M///xPK5m3ikh6LJDJhWwOjcYyh\n" +
                "uOh8CR5E7qN2F48w/Rn3JkOVEfYzR+x36DUE4qYZ9prP1EE9f8zurYqPNfGRRfou\n" +
                "pSANSXjvEd4WJgWeL6Hc0KnEbxTvGywdIZFopeyxyWFpi5Dhl0XoM5ViS5IqL2yG\n" +
                "6yJgtrnhkwRV6vTRr0pZlHul1LPLVf92wGHGe3VdiXRBwI7jAgMBAAGjazBpMB8G\n" +
                "A1UdIwQYMBaAFD5FdKKL0vFWjEYBZnhwJMYiwQOeMB0GA1UdDgQWBBQGUJPs1t5H\n" +
                "/XdkaQnJb4buZH4dZjAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgB\n" +
                "ZQMCATACMA0GCSqGSIb3DQEBCwUAA4IBAQBd4fpr0FEBAS7pX+anaaynR6VwZngp\n" +
                "VoG0SZ0FUwOTvUAU80cI8G0QJCcjQ7Ho6/KmeKznOb7zXJj0j6bmdlUvOTTQCDtd\n" +
                "Qh3Exa0x4Yv1s/wp3FVMFt8kc5V31ABQDj480IrFjHW5TZF7lsSE3eHpxKkl70oK\n" +
                "idmdbcVUbLHRm1+S8RYAUMrQn1kJpnP61URJZgiYoFzbCYgcswaIrf0oFZwdTZ/C\n" +
                "ueXiVLJdlbVkYp4u6FoC77Oo7vcIe8kw8i1byu2PaOmIjpmI4xjOBlYbwnqOeG7X\n" +
                "Z3vfgaVVMZ/fygknW+LpZZakKSnAkDun7Pm5WRNDCiRRn8rVL0NIYnuK\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1SelfIssuedCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1subsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Invalid Self-Issued inhibitPolicyMapping Test10" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDtDCCApygAwIBAgIBBDANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEnMCUGA1UEAxMeaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIz\n" +
                "MTA4MzAwMFowdzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNh\n" +
                "dGVzIDIwMTExRzBFBgNVBAMTPkludmFsaWQgU2VsZi1Jc3N1ZWQgaW5oaWJpdFBv\n" +
                "bGljeU1hcHBpbmcgRUUgQ2VydGlmaWNhdGUgVGVzdDEwMIIBIjANBgkqhkiG9w0B\n" +
                "AQEFAAOCAQ8AMIIBCgKCAQEAp5QAd+u/Uos7XJmpFiMxS2UfCoX4S7F2Z8X+H5aE\n" +
                "ROK+YmaczS0wMScaDNXiqifUvntr2PEVPGpjAdVg711oP4yJUO6yxljUqZl/DVV7\n" +
                "//qRPkD76MUCIxNx1dxLrsOd6PDmFV3ZcS1w5R6dB7E4AGV6jG2ikMHAp1UH69sJ\n" +
                "nxbMKCtpigzpxYTQtcH9+oB59lMkkAtSk0k09NvW0GHlDR6+suZgQHHfmJMV8C1+\n" +
                "WitpjZncCSlS6jc0QnYpGeytIPY3JVq5I9xaaiBsKLQAxf+N2XSNzs/SoUWDNfPy\n" +
                "tBlUdU9h8HmLx5ZB6OV8fF0G8jTH/kJ9qhOtzOBGuz26BwIDAQABo2swaTAfBgNV\n" +
                "HSMEGDAWgBRZuWxk6vOuluq2UVwljzvP7fWTDjAdBgNVHQ4EFgQUKnl4yMYjPGWd\n" +
                "wygY26eKCylWgpowDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUD\n" +
                "AgEwAzANBgkqhkiG9w0BAQsFAAOCAQEAmjzrR+7LxCOYhqiancHFg4jAXcy8IQNF\n" +
                "w8M3p9yWNIusPl3UwTBGf1o6nn7Pbp+sWPrqsdRETfOk+14+UpVFwwIu4tpNdNZN\n" +
                "KQGsovaMjGdr1ZawnSxGg7s7aRaTA/EN66brxdWQosoDVPByNjDIqzLx89UIcEPt\n" +
                "qVSK6UukAx6UqPPyZSj31V3VK/5zCvpaSmekzBdmRYoRyhTyCE9Siqqtqh+MOJYn\n" +
                "QRGpn1qPp+wZAqH9x4g+lsuUVjU3mll81rwQGHAWke/ZAbUmzZIkw2i6G08SJUhY\n" +
                "M6a3CsWate1y1nryzWjsVOzERK1X1dkKC5GsYm1X36COcZq+lkIshw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1SelfIssuedCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1subCACert).getOrThrow()
        val selfIssuedSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1SelfIssuedsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, selfIssuedSubCa, subCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Invalid Self-Issued inhibitPolicyMapping Test11" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDtDCCApygAwIBAgIBBTANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEnMCUGA1UEAxMeaW5oaWJp\n" +
                "dFBvbGljeU1hcHBpbmcxIFAxIHN1YkNBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIz\n" +
                "MTA4MzAwMFowdzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNh\n" +
                "dGVzIDIwMTExRzBFBgNVBAMTPkludmFsaWQgU2VsZi1Jc3N1ZWQgaW5oaWJpdFBv\n" +
                "bGljeU1hcHBpbmcgRUUgQ2VydGlmaWNhdGUgVGVzdDExMIIBIjANBgkqhkiG9w0B\n" +
                "AQEFAAOCAQ8AMIIBCgKCAQEA7Ubrj1mNP+NcBMyG2sr7H6cZ6y3lj+3xG6IfCsfO\n" +
                "TWglSnkb2CjlNIx/NjcGYn1YNubiDge31rG7CZNdO61NGtYgFxiAl3DQtg2HR+se\n" +
                "TWg7h8ZdTt6bCV2ccoGTajtCzKtfJbxEjC+ah94NvIk+IHcEu7JSf9A94efdSxnH\n" +
                "ESeVTat7aPkW7UlwTUZ/ua3oJ+1WwdUN3KgVmB9mDbATCYfiRk63RL/X1cKQZr2C\n" +
                "qYGnhh8ugZme/BgoClJrvDw0rYnepgPxYyV/XDTHe1F/KCclUCt2X74n9kwIGcyk\n" +
                "89i9pk4Tmr4WWDkSViuBBym+f/SDxnUFsgg4d2k265vaWQIDAQABo2swaTAfBgNV\n" +
                "HSMEGDAWgBRZuWxk6vOuluq2UVwljzvP7fWTDjAdBgNVHQ4EFgQUsEmMF+z3zVR8\n" +
                "cNCXb40wgeCroccwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUD\n" +
                "AgEwAjANBgkqhkiG9w0BAQsFAAOCAQEAShWF28EnDlNq3BCLCZnLPBE173JUcUzG\n" +
                "W8M3dA/+WBXujtD0xCKDnWMy+2QVNZkiao4ovBJBhZQXVVhkv1lGulx6kpuQwv/f\n" +
                "G8HB0esbeYOvGsRntOQM28vpioCKn2+7jG79SURwXGLO9k4QtQKEVrbOyQq+ki1O\n" +
                "r4ZUIBsKnsQe14SJJWN/vqAOfvoA6StL6l0LHoGr58TZdEyqINecPq0Uw+KWQLpN\n" +
                "oq//RG53Vm9P6yujzumBLf6llJII1izqotfy7jjFPS0azvJUO+LrtNMZB0Zf+8/L\n" +
                "0yj1hgvr5+em6YVvaOX4kG8xBQuSNYLyPF2O9aUo97lqZLKvyNm7Kw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1SelfIssuedCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1subCACert).getOrThrow()
        val selfIssuedSubCa = X509Certificate.decodeFromPem(inhibitPolicyMapping1P1SelfIssuedsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, selfIssuedSubCa, subCa, selfIssuedCa, ca, trustAnchorRoot)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }
})