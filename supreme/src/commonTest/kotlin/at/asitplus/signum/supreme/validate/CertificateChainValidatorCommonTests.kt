package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodeNameConstraints
import io.kotest.core.spec.style.FreeSpec

open class CertificateChainValidatorCommonTests : FreeSpec({

    "Valid chain" {
        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIBxDCCAWmgAwIBAgIUTqAymUGDwq1ksSBDPKc2IjkBQgUwCgYIKoZIzj0EAwIw\n" +
                "NzENMAsGA1UEBwwEQ2l0eTEVMBMGA1UECgwMT3JnYW5pemF0aW9uMQ8wDQYDVQQD\n" +
                "DAZSb290Q0EwHhcNMjUwNDI4MDg0MDUyWhcNMzUwNDI2MDg0MDUyWjA3MQ0wCwYD\n" +
                "VQQHDARDaXR5MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xDzANBgNVBAMMBlJvb3RD\n" +
                "QTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNs2dL4mKtv3ULxSn3uvksQZWi25\n" +
                "OrO+L628Bt//IEhSytFnzwUICREoZGzom3MsjokhQVWvQfIkQW7LwI0R1B+jUzBR\n" +
                "MB0GA1UdDgQWBBQPTgzqEsW/0b5emnBFtftR5t7Q3jAfBgNVHSMEGDAWgBQPTgzq\n" +
                "EsW/0b5emnBFtftR5t7Q3jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kA\n" +
                "MEYCIQCVxLdC098JAidcCJMZXsbI51+rF6+vLStusaMvC5e6sQIhAMFiNbhBDPMK\n" +
                "W345ihosvbVPVTdrsOfM2fUjE2uegszo\n" +
                "-----END CERTIFICATE-----\n"
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkTCCATegAwIBAgIUV6jFO6LQFN4RX43PyBaq3APpTGUwCgYIKoZIzj0EAwIw\n" +
                "NzENMAsGA1UEBwwEQ2l0eTEVMBMGA1UECgwMT3JnYW5pemF0aW9uMQ8wDQYDVQQD\n" +
                "DAZSb290Q0EwHhcNMjUwNDI4MDg0MTMwWhcNMjYwNDI4MDg0MTMwWjAWMRQwEgYD\n" +
                "VQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPIMJgG7\n" +
                "2p/Xv2Wp7aaDSDQfNZjoy6b14zBa6xlyjn3f/XaCpPBXAyjeJE7+HnEuF+f4reQq\n" +
                "k0Ou1vk0jG1Xx2+jQjBAMB0GA1UdDgQWBBSkgC9smYe6Z2VDbYYyU4al2R7rsDAf\n" +
                "BgNVHSMEGDAWgBQPTgzqEsW/0b5emnBFtftR5t7Q3jAKBggqhkjOPQQDAgNIADBF\n" +
                "AiAi1BvtfScmfQQ/OleiYwzSKJs2H2nXJ2RWXYyOItCMVwIhAIx3ULJH5ApCEU/D\n" +
                "1o3IgOXA23BoXqTvZzEr52CJRyVj\n" +
                "-----END CERTIFICATE-----\n"

        val certwithKeyUsage = "-----BEGIN CERTIFICATE-----\n" +
                "MIIHnTCCBoWgAwIBAgIQB3a13cqDpLnKWY9ddx+eRjANBgkqhkiG9w0BAQsFADB1\n" +
                "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n" +
                "d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk\n" +
                "IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTE2MDMwOTAwMDAwMFoXDTE4MDMxNDEy\n" +
                "MDAwMFowggEhMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjETMBEGCysG\n" +
                "AQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEQMA4GA1UE\n" +
                "BRMHNDMzNzQ0NjESMBAGA1UECRMJU3VpdGUgOTAwMRcwFQYDVQQJEw4xMzU1IE1h\n" +
                "cmtldCBTdDEOMAwGA1UEERMFOTQxMDMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD\n" +
                "YWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRYwFAYDVQQKEw1Ud2l0\n" +
                "dGVyLCBJbmMuMRkwFwYDVQQLExBUd2l0dGVyIFNlY3VyaXR5MRQwEgYDVQQDEwt0\n" +
                "d2l0dGVyLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIImPpn\n" +
                "AAVVtgthDhrXtYrBzAO+PBf7lPfZ+kyfRmCcaq19OuU0WhKwsguq7JbhWIEvrWCr\n" +
                "R5Np44R1U8H5D7lGq57qqxiYjGhUCFFlQxphlydcXg8V6c0Wq91RW3Yv/NMRmZ3S\n" +
                "pj2HAnXmJJbiBD4UnPp+uHFCNwC1sIriM5WL2j/7Y003YtUcAuowftwNU9XUC7ij\n" +
                "EBNtH4mUC2qURGcpgq3m1bBS/JVXBtbRImaE05IqAseUVt9VP8IT8nwWeDOhU/d3\n" +
                "l1y3lgXVRPS/74MiXXrmj+Ss3zSetg8KU/Aa23E3aZL2FKkcdWVyRSQJOyxq17lp\n" +
                "pdzfbZxr/MaiWzECAwEAAaOCA3kwggN1MB8GA1UdIwQYMBaAFD3TUKXWoK3u80pg\n" +
                "CmXTIdT4+NYPMB0GA1UdDgQWBBSfYnuyiA7uG3ngaSTluj9HpgsC8DAnBgNVHREE\n" +
                "IDAeggt0d2l0dGVyLmNvbYIPd3d3LnR3aXR0ZXIuY29tMA4GA1UdDwEB/wQEAwIF\n" +
                "oDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYDVR0fBG4wbDA0oDKg\n" +
                "MIYuaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItZXYtc2VydmVyLWcxLmNy\n" +
                "bDA0oDKgMIYuaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTItZXYtc2VydmVy\n" +
                "LWcxLmNybDBLBgNVHSAERDBCMDcGCWCGSAGG/WwCATAqMCgGCCsGAQUFBwIBFhxo\n" +
                "dHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAcGBWeBDAEBMIGIBggrBgEFBQcB\n" +
                "AQR8MHowJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBSBggr\n" +
                "BgEFBQcwAoZGaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hB\n" +
                "MkV4dGVuZGVkVmFsaWRhdGlvblNlcnZlckNBLmNydDAMBgNVHRMBAf8EAjAAMIIB\n" +
                "fAYKKwYBBAHWeQIEAgSCAWwEggFoAWYAdgCkuQmQtBhYFIe7E6LMZ3AKPDWYBPkb\n" +
                "37jjd80OyA3cEAAAAVNdgFLZAAAEAwBHMEUCICZCA9wZjkyHJRy3UTCYnwI21m/U\n" +
                "XKRXWc7US9arx68qAiEAtK1UZMDl2wRt/o1OxInzFdQCQ+2QTIvLbHe5slXu6boA\n" +
                "dQBo9pj4H2SCvjqM7rkoHUz8cVFdZ5PURNEKZ6y7T0/7xAAAAVNdgFKcAAAEAwBG\n" +
                "MEQCIGF6AFQ8TKA8AqktUZ/45JJuKYHCIFIkqcPWIIDLWIZmAiA5PVUV5BBCM2AK\n" +
                "ce/CeXCyim1y140g/4RxghYW6sNCNwB1AFYUBpov18Ls0/XhvUSyPsdGdrm8mRFc\n" +
                "wO+UmFXWidDdAAABU12AU6YAAAQDAEYwRAIgXUM1kBRW2bTGAqVvy/aDoYTrdKvM\n" +
                "I6x5p0FF2S+jGmkCIFmAWDXHV/YBi4thS8HGZc3iVCh5wwaCGM3kztEaUYmQMA0G\n" +
                "CSqGSIb3DQEBCwUAA4IBAQC7+PUbZaNQAx8YEMg1Uy+cih5Iar3l5ljJ0eih/KsD\n" +
                "Qo9Y8woYppEuwVC3cN0V2q0I8RXSRE105BgrZbYF2fn32CRs21/sbH0/v6VMonNo\n" +
                "OEJBzeL20fjYidN1Sr39q02e7kjJNCPVg8yTlRREpSXlsfwXWFOnACSBwpRzmD43\n" +
                "bRKVH6zjIPiy2wmxXP6ibb3p0ITHnosxLsf3pWXjL/YeWqQq6mUDMRKmeCRR3k1E\n" +
                "03kXQyxV4AD4hccLqP4K6m17dOkpWbKWNN+/wxWy/ApMuP0hNPgoZSLQBaMidNzh\n" +
                "Y63izHj1KcOdLNg8VVCCEPoEX8IlbLMIY/YTfN5XAFjs\n" +
                "-----END CERTIFICATE-----"

        val certBasicConstraintPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIICljCCAhugAwIBAgIQf/Tlzjamofpe4ZFsCNObfDAKBggqhkjOPQQDAzBHMQsw\n" +
                "CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU\n" +
                "MBIGA1UEAxMLR1RTIFJvb3QgUjQwHhcNMjMxMjEzMDkwMDAwWhcNMjkwMjIwMTQw\n" +
                "MDAwWjA7MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZp\n" +
                "Y2VzMQwwCgYDVQQDEwNBRTEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR9Clzb\n" +
                "GcDZDNJ5v+Jo/EXiF/q+TVkbiR3KwDlvjO3AR6EviCv1zDSG9ZtRjQwwV/HYAWTb\n" +
                "lGC54Faji+ZJgGqqo4H0MIHxMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggr\n" +
                "BgEFBQcDATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRIiWD5o30M6gAk\n" +
                "otyfB85GiKgyOjAfBgNVHSMEGDAWgBSATNbrdP9JNqPV2Py1PsVq8JQdjDA0Bggr\n" +
                "BgEFBQcBAQQoMCYwJAYIKwYBBQUHMAKGGGh0dHA6Ly9pLnBraS5nb29nL3I0LmNy\n" +
                "dDArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vYy5wa2kuZ29vZy9yL3I0LmNybDAT\n" +
                "BgNVHSAEDDAKMAgGBmeBDAECATAKBggqhkjOPQQDAwNpADBmAjEAmdMod3458+nB\n" +
                "HDNg8KNDbxBK27go5UPnjRbgl/QweOAgXHA8hFzoCYMp8QlSzjwrAjEA+Vf20EHl\n" +
                "KBYnP1hBSz11CIZ1MTXazV+wEL1Ep45WDR1/Pb3+QzLbviujkatk3MMe\n" +
                "-----END CERTIFICATE-----\n"

        val certNameConstraintsPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDPzCCAiegAwIBAgIULfD3GEBBKGfotQCdDBx07Ek9fvgwDQYJKoZIhvcNAQEL\n" +
                "BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI1MDUxMjA4NTkwNloXDTM1\n" +
                "MDUxMDA4NTkwNlowGTEXMBUGA1UEAwwOU3Vib3JkaW5hdGUgQ0EwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHa41Nu4uJ6OWVoNum60QYc1JrtPWXZdj9\n" +
                "d75bjpPMsyxs5ocZFEJIklHtDcNCPW/hTkCbniT3UeZmMEWa1KqVKOm6G3G4neQP\n" +
                "lG4QEqAblTBAbgCO6c+ZoFjpifkBin+/RtUJ6IjADDP3Y/HfXp1OYK+KKKopydK0\n" +
                "5mKbrbRCI0xafrrcIsdAGQunjaA6koklilQV+vIhIOnVKQnoPMzi0InZI9maTSpb\n" +
                "oXGIhIyc1ps5K6qZhqn03Nn7reRh4OGDkIUwuxg+YCpLQ3BWV4ZOQ4Wqv94PnrAp\n" +
                "stqCKheYzpi6EPfULewTDSco8swPdvQW2/NAjBdlhRqunJBM65k1AgMBAAGjgYAw\n" +
                "fjAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQUfu2pmh9o\n" +
                "F6uJCQlzXYL2RBttXykwHwYDVR0jBBgwFoAUr996qI0ZigTlofGifs1QW4RPTpUw\n" +
                "HgYDVR0eAQH/BBQwEqAQMA6BDC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOC\n" +
                "AQEANXFCDp5JBvrXoUnX23/EqyorQh6lc2tot3LIsMlG7b2Qxb1cPij+g2kB+WWE\n" +
                "//ZD8dNAoaXF2zyHKHeyJsnZ93CIyfth8MlVUR7HDgCP39YYUbJXrgoi/sPDcMgr\n" +
                "BdE9TwplgeSwbklB2dfk0LgJMYn9dvi6jCm+5Vg1Xfmloerc2b1/t0Yauk+PDUlr\n" +
                "B42AvB3nQlf22JUTyKTikOPsHUAIWXxQiAltAzBUayVLLpMoo6JwBm6b7Fusg8x9\n" +
                "HmZLqDZ0S4Cf5oCFez1rFEtwAOJO3CcRQIDDorudJ517SgrXI0827goWcm/Ntoww\n" +
                "Dv3+phSDVM2G5J2fTf4kDkZ5nw==\n" +
                "-----END CERTIFICATE-----\n"

        val certSeveralNameConstraintsPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEgjCCA2qgAwIBAgIULfD3GEBBKGfotQCdDBx07Ek9fvwwDQYJKoZIhvcNAQEL\n" +
                "BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI1MDUxNjA3NTMxNFoXDTM1\n" +
                "MDUxNDA3NTMxNFowGTEXMBUGA1UEAwwOU3Vib3JkaW5hdGUgQ0EwggIiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4ICDwAwggIKAoICAQCSJBytSBoa0wKZgpWzTUDryGHq7jWnpnzC\n" +
                "iUjMHcl5gCyB/C+2KP7Egs2vmJRA71azKPxEzVBXgReOldVliEu+PvaKFpVUIzRt\n" +
                "g8yx+Sd+DTjnwVpEFfZ+Ynt7LjtsypWe7rW2UspMDcfZ9IP+Y4WoADRba83PvFUQ\n" +
                "yihLfoWWnPxSwtAx71cpQdCx6kAml10o5dSEaVa/W2UDhHK0zBHnPRb8rC9z7B3H\n" +
                "p9tszFTxa1GYtWhMzObAH8zEcKFjIWLCqfomq2pZMnnEROVvCzWI6tU4ImSShfKT\n" +
                "X+GFgsE6/jpL8upQn/4oV6InJ44QrTNA0xQeDRpWtOU5RRC3R+mSwHV/CUVRdOwB\n" +
                "MqWCzXWMr5LDzc5YH848eyhXhtA9ktqvQoKXMUdXIpqMrB3yUjxa8mJ/GlNaBcCo\n" +
                "B80ldGrWUsP+M0T3AqTbczcIeaE6+TseCiz2buoizfrCd4ATcWq70w80g3TzguRa\n" +
                "kV0mFFnMC2RlWfZ9JcUTCGaID+il1UeCEmsWPGbtNITJ4Mg2px14PNDoQFJ+SbMI\n" +
                "sN5hEMUMgxbb7viYjq9Go/AMfpYbrPd695YPsxPBgfJymUxoGSP+t0uQdeyvLA3G\n" +
                "09uoORQfSTFCe6c/5hL+O+gPMMxyyJp1Fzlj0jdu1J575cxPl7TP4z53TKNE+t37\n" +
                "xB/JRVm1KQIDAQABo4HDMIHAMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgEG\n" +
                "MB0GA1UdDgQWBBSHl3ksfqvoGg1PlLN6W3+bBvfcbzAfBgNVHSMEGDAWgBSv33qo\n" +
                "jRmKBOWh8aJ+zVBbhE9OlTBgBgNVHR4BAf8EVjBUoFIwDYILZXhhbXBsZS5jb20w\n" +
                "DoEMLmV4YW1wbGUuY29tMBSGEmh0dHA6Ly9leGFtcGxlLmNvbTAbpBkwFzEVMBMG\n" +
                "A1UECgwMRXhhbXBsZSBDb3JwMA0GCSqGSIb3DQEBCwUAA4IBAQAPxXSzOgCZ0jdV\n" +
                "M1MouDkZ0XWXQvenkLdfgty9OAerFpH7wl/aWPRFVTTT5CSeQ8gfLLwf8maWNGaS\n" +
                "4SSUv+ICocu+j7Gj5HA5MhClJ523KKnJogmKWf8UG+QkKTW79GBJ9Hoy2irgEcT4\n" +
                "SujmT3MCMu8ulXywRHE1m43fEkt6UA5RM1kg/vwSXDu2iG9ybBbPyTkcV4svLggL\n" +
                "r5LDnChh6IlgZiZhvFukDxBTufNa0jb27A1VZ5WEKGIFhklv0Bs/D37BZpgscOH8\n" +
                "1mqaml570pa/yjGqLDP8mMqRp/OetGCxRT1QD11j5xnfDN0ONIqaSwLAtTzci74K\n" +
                "j4+zvg3l\n" +
                "-----END CERTIFICATE-----\n"

        val certNcpermitted = "-----BEGIN CERTIFICATE-----\n" +
                "MIIC3DCCAcSgAwIBAgITBm/6kAXHpw8f3guDBcRXNLfl5DANBgkqhkiG9w0BAQsF\n" +
                "ADAXMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwHhcNMTUwNjI5MDkzMjQ5WhcNMTYw\n" +
                "NjI4MDkzMjQ5WjAXMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQCylTa0WkLvIXB4sWoPdv5iL3idlVHKR+ncODKL\n" +
                "nwQ2Jtd990MfakOFRLrJFF1tfPL4qyRbbyMyrgCOoKBCAuIdBZfBDH3JWFjxGy8J\n" +
                "Yls8yVeAVKreV18HmLvAsBL3bnr7Gk3vpznrfoG5rn5T/fL0cqqTXFV8zQhjHiEo\n" +
                "zftSaoq0LOxsSgFdxXS8e8K6RMvLCZPcMpI4fo1Kq2QBT2J1x1/Hq/VnK132cs0g\n" +
                "TOyiTyyJfvRmlqdXowh7Jf8LQB4mM6gc023fEdQ+HH6JYX1vDQVxaiTM6KMYJNv/\n" +
                "l4gchP3jknOfZffwGGdXQrtUMhQmltnSqV5nY/G2OGm/Z0pdAgMBAAGjITAfMB0G\n" +
                "A1UdHgEB/wQTMBGgDzANggt6b21iby5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
                "WcDkqLUsvIBfTzKncOSiy08lcwu+kq/8rybh4HoHEimcy47M+XLPnXqwA7jedz8M\n" +
                "Znog64O9wZ1olWs+GGrGcJAth2BqdNtRvb6/o2Hq29vNbCQeYRlOTdNzGnb5v6fB\n" +
                "HEPvuB7UNKyaJ2tF50oxqhg8ojgauX3fuanCtR9Obx/2U8e8zfBIauX13XfpoCyt\n" +
                "efeL97kYz+XIQwG8TvXpNdHO0QjmA/ToR7E5BbSo2e4cicKEomtLhKI7EXa+Ofwg\n" +
                "HoyVC8wl97nm7mwI7iFYK5f8YoqwILxKEP6O9+pZEOveqdKfx4+WAgeGyDvBwAjf\n" +
                "Ej8vkawtdgV/96ajsIqzDQ==\n" +
                "-----END CERTIFICATE-----"

        val certInvalidNetMask = "-----BEGIN CERTIFICATE-----\n" +
                "MIIC8TCCAdmgAwIBAgITBm/Wnt8Tt9uB01YkE0oW0WAn8DANBgkqhkiG9w0BAQsF\n" +
                "ADAXMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwHhcNMTUwNjI3MjMzNDI1WhcNMTYw\n" +
                "NjI2MjMzNDI1WjAXMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQCylTa0WkLvIXB4sWoPdv5iL3idlVHKR+ncODKL\n" +
                "nwQ2Jtd990MfakOFRLrJFF1tfPL4qyRbbyMyrgCOoKBCAuIdBZfBDH3JWFjxGy8J\n" +
                "Yls8yVeAVKreV18HmLvAsBL3bnr7Gk3vpznrfoG5rn5T/fL0cqqTXFV8zQhjHiEo\n" +
                "zftSaoq0LOxsSgFdxXS8e8K6RMvLCZPcMpI4fo1Kq2QBT2J1x1/Hq/VnK132cs0g\n" +
                "TOyiTyyJfvRmlqdXowh7Jf8LQB4mM6gc023fEdQ+HH6JYX1vDQVxaiTM6KMYJNv/\n" +
                "l4gchP3jknOfZffwGGdXQrtUMhQmltnSqV5nY/G2OGm/Z0pdAgMBAAGjNjA0MDIG\n" +
                "A1UdHgEB/wQoMCagJDAihyAA/wAAAAAAAAAAAAAAAAAA/////wAA/////wD/AAAA\n" +
                "ADANBgkqhkiG9w0BAQsFAAOCAQEALGCUUKrfrDkuezZmG5ibkAYOMl2jwc6qmyRO\n" +
                "GzAeh1xgJpyG4Cz6E57PZwFJiU7WsagW75xiuhyt3BvjEob9TaHmkPka16SdJBP2\n" +
                "6fkzUHu9HKJbJ5GNzPrcJJG0IQB9Vdqs2D3qrpNC6IQ80PLPaT8Lq3L6Na8c2VrQ\n" +
                "Y80eHVxiTllDFy8NGIu5nvuKinLSW/O/WNH7M0pkQ9clFR7R+bGNwGrTJ9pKhgGK\n" +
                "fNJU7CT5HTViMQmN49c3B6JrdBblBI/q3SLTqxqa0Qwp2ZH2fYjCszO3QdpPlbQD\n" +
                "N8kfs6qmNhkvfIDWMNdQBqhnhuOJ8FJLo1/xYP1ziigg+ajN8g==\n" +
                "-----END CERTIFICATE-----"

        val certNcPermittedExcluded = "-----BEGIN CERTIFICATE-----\n" +
                "MIIC9DCCAdygAwIBAgITBm/3q66sET2C+Ko/TLr1EHnvdTANBgkqhkiG9w0BAQsF\n" +
                "ADAXMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwHhcNMTUwNjI5MDY0ODQ4WhcNMTYw\n" +
                "NjI4MDY0ODQ4WjAXMRUwEwYDVQQDDAxjcnlwdG9ncmFwaHkwggEiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQCylTa0WkLvIXB4sWoPdv5iL3idlVHKR+ncODKL\n" +
                "nwQ2Jtd990MfakOFRLrJFF1tfPL4qyRbbyMyrgCOoKBCAuIdBZfBDH3JWFjxGy8J\n" +
                "Yls8yVeAVKreV18HmLvAsBL3bnr7Gk3vpznrfoG5rn5T/fL0cqqTXFV8zQhjHiEo\n" +
                "zftSaoq0LOxsSgFdxXS8e8K6RMvLCZPcMpI4fo1Kq2QBT2J1x1/Hq/VnK132cs0g\n" +
                "TOyiTyyJfvRmlqdXowh7Jf8LQB4mM6gc023fEdQ+HH6JYX1vDQVxaiTM6KMYJNv/\n" +
                "l4gchP3jknOfZffwGGdXQrtUMhQmltnSqV5nY/G2OGm/Z0pdAgMBAAGjOTA3MDUG\n" +
                "A1UdHgEB/wQrMCmgDzANggt6b21iby5sb2NhbKEWMBSkEjAQMQ4wDAYDVQQDDAV6\n" +
                "b21ibzANBgkqhkiG9w0BAQsFAAOCAQEAaSyuJlNVZkkwHn4V9EglOTm6DC/lzrLm\n" +
                "1y/qcXsY2NXgCRfpZal0lx25M7Dl2G1IOBG+Ub1/ua0NASlpd6BeZ4prmcD4OBib\n" +
                "oAhMJxt8QNNwkcMG5PnI6reQz5MiRwGOCEAZeX1opIijn/tO49RliEnEQCKbsvdr\n" +
                "d+0ieNhLdoxazW/k3UCu+Vdd1b3TOLERrhm/xGj2W9AhWAv7GIovhBGGfuD6BFmC\n" +
                "uHjxoG0So//NiHTfZ9eukgW3rNSbjQjtnC8BsRzUdhX/YBvw+SKkeVL2oz7+lRgD\n" +
                "fhba3FtwUfCIX3y/UAc0E0+x9bLFDyQXYNHAXq+q72sOkLXgAH8bfQ==\n" +
                "-----END CERTIFICATE-----"

        val cert = X509Certificate.decodeFromPem(certNcPermittedExcluded).getOrThrow()
        val extension =
            cert.tbsCertificate.extensions?.find { it.oid == KnownOIDs.nameConstraints_2_5_29_30 }
        println(extension)
        val nc = extension?.decodeNameConstraints()
        println(nc?.permitted?.trees)
        println(nc?.excluded?.trees)
    }
})