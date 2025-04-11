@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.attestation.android.*
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.attestation.AttestationData.Level
import com.google.android.attestation.AuthorizationList
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.bouncycastle.util.encoders.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.jvm.optionals.getOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

@OptIn(ExperimentalStdlibApi::class)
class BasicParsingTests : FreeSpec({


    "Calyx" {
        val crt = Asn1Element.parseFromDerHexString(
            "30 82 02 99 30 82 02 3F A0 03 02 01 02 02 01 01 30 0A 06 08 2A 86 48 CE 3D 04 03 02 30 39 31 29 30 27 06 03 55 04 03 13 20 62 38 34 62 32 37 35 33 33 63 62 63 32 39 34 38 64 39 62 31 39 37 66 34 32 63 62 63 39 65 64 66 31 0C 30 0A 06 03 55 04 0A 13 03 54 45 45 30 1E 17 0D 32 35 30 33 33 31 31 30 32 31 32 37 5A 17 0D 34 38 30 31 30 31 30 30 30 30 30 30 5A 30 19 31 17 30 15 06 03 55 04 03 0C 0E 42 61 72 74 73 63 68 6C C3 BC 73 73 65 6C 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 04 DC F1 96 F5 38 E7 2E B7 08 96 11 7D 1C 8F 81 C7 78 E1 CC 3F 53 AA 9A A0 18 87 A6 11 EE A3 E7 7C 94 9F 38 01 65 19 04 D4 2D 10 A3 90 50 3C 77 C8 0B 87 CF 35 E2 53 0C B9 9C F9 55 36 9E 95 45 60 A3 82 01 56 30 82 01 52 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 07 80 30 82 01 3E 06 0A 2B 06 01 04 01 D6 79 02 01 11 04 82 01 2E 30 82 01 2A 02 02 01 2C 0A 01 01 02 02 01 2C 0A 01 01 04 10 8D 37 55 49 8F 93 5F 38 1F 74 15 9A 3A 55 50 1F 04 00 30 62 BF 85 3D 08 02 06 01 95 EB B8 6D 6F BF 85 45 52 04 50 30 4E 31 28 30 26 04 21 61 74 2E 61 73 69 74 70 6C 75 73 2E 63 72 79 70 74 6F 74 65 73 74 2E 61 6E 64 72 6F 69 64 41 70 70 02 01 01 31 22 04 20 94 1A 45 13 A3 02 75 63 D3 A6 EA 48 EE E8 5B A4 5E B9 F6 9C EE A1 9E F0 EB B1 7F 10 0B FC 88 78 30 81 A1 A1 05 31 03 02 01 02 A2 03 02 01 03 A3 04 02 02 01 00 A5 05 31 03 02 01 04 AA 03 02 01 01 BF 83 77 02 05 00 BF 85 3E 03 02 01 00 BF 85 40 4C 30 4A 04 20 4A B5 28 25 88 ED 1A 1F B0 8E 84 89 48 48 01 A3 71 04 CA ED F1 81 61 EC 45 30 4A 33 05 86 05 B8 01 01 FF 0A 01 01 04 20 52 10 6A 40 6C CD E0 D1 D9 90 91 A9 AA 6C A9 CD C4 93 15 73 11 43 8D AF D8 DC D1 92 08 4D 00 49 BF 85 41 05 02 03 02 49 F0 BF 85 42 05 02 03 03 17 06 BF 85 4E 06 02 04 01 34 FE 5D BF 85 4F 06 02 04 01 34 FE 5D 30 0A 06 08 2A 86 48 CE 3D 04 03 02 03 48 00 30 45 02 21 00 F9 05 C0 C9 8A B0 63 4E 69 A1 A7 85 D0 78 DE CE 00 34 36 7E 2E A7 5C 84 50 90 DB 10 73 5C 11 0D 02 20 72 DA 09 AF A7 5C 86 D3 23 FE F9 84 9F 60 C6 28 72 21 2E CF 03 E7 FB B3 E5 0F B1 D9 04 A7 94 3D"
        )
        val attestationExtension = X509Certificate.decodeFromTlv(crt.asSequence()).androidAttestationExtension
        println(attestationExtension!!.encodeToTlv().prettyPrint())
    }

    "From Warden" - {
        withData(
            AttestationData(
                "Android Emulator RSA",
                challengeB64 = "dRGIuJhE8j0t6lYbVfusgE17CWvGWXYpnTxcx0BZ87E=",
                attestationProofB64 = listOf(
                    """
                    MIIE+zCCBGSgAwIBAgIBATANBgkqhkiG9w0BAQsFADB2MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UE
                    CgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMSkwJwYDVQQDDCBBbmRyb2lkIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEtl
                    eTAeFw03MDAxMDEwMDAwMDBaFw02OTEyMzEyMzU5NTlaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MIICIjANBgkq
                    hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuOwpW9boeY2+tihDBAja17fOToCT2mdgUV9HC1xyN8y1pxUTEGGmWxaiVgy49ktl4Qoo
                    MwOJd8rqcz/uyt4/okE6RvR4cpezPQ/h53eERDoasmxC6wERwg2MfA0Lqo7pY79gGmc2RXdMdFmMjSDJ0zQclhFJR5/zJhiqtN/R
                    Y2nIV9B/urBgRVxwcAMBsQ59zu4SM6O1aomBqxM9+IuC5ylcxwRgWkqLgjIjo+haXuemfKsexXSI2AIu7sOm5GlMngwNVX1/2GBC
                    mYMn+sAcRtoOJrGrrYaUpih8fi4oQnZirEkSaUErDdiDVkawhcNhVYZQ9puS75p011ZlJHg3Vlq3pgW7NeB0P8dDpSviqwvBgKyE
                    HUf+a5ggKP+EWpJ+i62rOod7iNvSdpcQLDfbKmlo4nVAziM1aqafleV06CB1yABYe8SaSPpZKkPUK3HQPwsqZzjSHyZwUu6RSZRh
                    iGsiYk2BwrhjWvLHRUmXbHP6HgIZtSOVhdrDUx3S/B2JJ2IxGZ6YCTnTaj+ajg0+XurkoWQfcAKzlm62pnReCjPlljky6kIl/tD/
                    0k9aHall6M2QqJ29wgaGhDtFWISjbwifUHXH1wt9pBKCRack0zFJQ6i8CsRmPgsI7SXW6OZzwz5Jzu1stjFXRzTgcmNBkBHjkigU
                    5SNAancp6+LMFdMCAwEAAaOCAWowggFmMAsGA1UdDwQEAwIHgDCCATQGCisGAQQB1nkCAREEggEkMIIBIAIBBAoBAAIBKQoBAAQg
                    dRGIuJhE8j0t6lYbVfusgE17CWvGWXYpnTxcx0BZ87EEADCB66EIMQYCAQICAQOiAwIBAaMEAgIQAKUIMQYCAQICAQS/gUgFAgMB
                    AAG/g3cCBQC/hT0IAgYBimuBRsi/hT4DAgEAv4VATDBKBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAoBAgQg
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC/hUEFAgMBrbC/hUIFAgMDFRu/hUVEBEIwQDEaMBgEE2F0LmFzaXRwbHVz
                    LmF0dHRlc3QCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwADAfBgNVHSMEGDAWgBTUDBAb+M1jufc5UrUO
                    E1ym15mThjANBgkqhkiG9w0BAQsFAAOBgQCiCU5bJUV5sq+o8WEHspiM4A8WCtujZCC7gyHvemgn19qVIVRiU09Arae/dJnISvdh
                    yUKNmMDHyozgLUyd4+YI1Vg1MR3O1Qm36esvHMeqeM/J6bon3ROsYZVvBMn6US4fx8mVM1Sz7rXqBu/JoomySVSSr5QnPDMl3V8z
                    GGYohQ==
                    """,
                    """
                    MIICtjCCAh+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNV
                    BAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDAeFw0xNjAxMDQxMjQwNTNa
                    Fw0zNTEyMzAxMjQwNTNaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4x
                    EDAOBgNVBAsMB0FuZHJvaWQxKTAnBgNVBAMMIEFuZHJvaWQgU29mdHdhcmUgQXR0ZXN0YXRpb24gS2V5MIGfMA0GCSqGSIb3DQEB
                    AQUAA4GNADCBiQKBgQDAgyPcVogbuDAgafWwhWHG7r5/BeL1qEIEir6LR752/q7yXPKbKvoyABQWAUKZiaFfz8aBXrNjWDwv0vIL
                    5Jgyg92BSxbX4YVBeuVKvClqOm21wAQIO2jFVsHwIzmRZBmGTVC3TUCuykhMdzVsiVoMJ1q/rEmdXX0jYvKcXgLocQIDAQABo2Yw
                    ZDAdBgNVHQ4EFgQU1AwQG/jNY7n3OVK1DhNcpteZk4YwHwYDVR0jBBgwFoAUKfrxrMxN0kyWQCd1trDpMuUH/i4wEgYDVR0TAQH/
                    BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADgYEAni1IX4xnM9waha2Z11Aj6hTsQ7DhnerCI0YecrUZ
                    3GAi5KVoMWwLVcTmnKItnzpPk2sxixZ4Fg2Iy9mLzICdhPDCJ+NrOPH90ecXcjFZNX2W88V/q52PlmEmT7K+gbsNSQQiis6f9/VC
                    LiVE+iEHElqDtVWtGIL4QBSbnCBjBH8=  
                    """,
                    """
                    MIICpzCCAhCgAwIBAgIJAP+U2d2fB8gMMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
                    MRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQwHhcNMTYwMTA0
                    MTIzMTA4WhcNMzUxMjMwMTIzMTA4WjBjMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRh
                    aW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
                    gQCia63rbi5EYe/VDoLmt5TRdSMfd5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmgMdsGUmX4
                    RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm+Vfkl5YLCazOkjWFmwIDAQABo2MwYTAdBgNVHQ4EFgQU
                    KfrxrMxN0kyWQCd1trDpMuUH/i4wHwYDVR0jBBgwFoAUKfrxrMxN0kyWQCd1trDpMuUH/i4wDwYDVR0TAQH/BAUwAwEB/zAOBgNV
                    HQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADgYEAT3LzNlmNDsG5dFsxWfbwjSVJMJ6jHBwp0kUtILlNX2S06IDHeHqcOd6os/W/
                    L3BfRxBcxebrTQaZYdKumgf/93y4q+ucDyQHXrF/unlx/U1bnt8Uqf7f7XzAiF343ZtkMlbVNZriE/mPzsF83O+kqrJVw4OpLvtc
                    9mL1J1IXvmM=    
                    """
                ),
                isoDate = "2023-09-06T17:19:09Z",
                pubKeyB64 = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuOwpW9boeY2+tihDBAja17fOToCT2mdgUV9HC1xyN8y1" +
                        "pxUTEGGmWxaiVgy49ktl4QooMwOJd8rqcz/uyt4/okE6RvR4cpezPQ/h53eERDoasmxC6wERwg2MfA0Lqo7pY79gGmc2" +
                        "RXdMdFmMjSDJ0zQclhFJR5/zJhiqtN/RY2nIV9B/urBgRVxwcAMBsQ59zu4SM6O1aomBqxM9+IuC5ylcxwRgWkqLgjIj" +
                        "o+haXuemfKsexXSI2AIu7sOm5GlMngwNVX1/2GBCmYMn+sAcRtoOJrGrrYaUpih8fi4oQnZirEkSaUErDdiDVkawhcNh" +
                        "VYZQ9puS75p011ZlJHg3Vlq3pgW7NeB0P8dDpSviqwvBgKyEHUf+a5ggKP+EWpJ+i62rOod7iNvSdpcQLDfbKmlo4nVA" +
                        "ziM1aqafleV06CB1yABYe8SaSPpZKkPUK3HQPwsqZzjSHyZwUu6RSZRhiGsiYk2BwrhjWvLHRUmXbHP6HgIZtSOVhdrD" +
                        "Ux3S/B2JJ2IxGZ6YCTnTaj+ajg0+XurkoWQfcAKzlm62pnReCjPlljky6kIl/tD/0k9aHall6M2QqJ29wgaGhDtFWISj" +
                        "bwifUHXH1wt9pBKCRack0zFJQ6i8CsRmPgsI7SXW6OZzwz5Jzu1stjFXRzTgcmNBkBHjkigU5SNAancp6+LMFdMCAwEA" +
                        "AQ==",
                packageName = "at.asitplus.atttest",
                expectedDigest = Base64.decode("NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU="),
                attestationLevel = AttestationData.Level.SOFTWARE
            ),
            AttestationData(
                "bq Aquaris X with LineageOS",
                challengeB64 = Base64.toBase64String("foobdar".encodeToByteArray()),
                attestationProofB64 = listOf(
                    "MIICkDCCAjagAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDE7MDkGA1UEAwwyQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoX5eWkxsJOk2z6S5tclt6bOyJhS3b+2+ULx3O3zZAwFNrbWP52YnQzp/lsexI99lx/Z5NRzJ9x0aDLdIcR/AyqOB9jCB8zALBgNVHQ8EBAMCB4AwgcIGCisGAQQB1nkCAREEgbMwgbACAQIKAQACAQEKAQEEB2Zvb2JkYXIEADBev4U9BwIFAKtq1Vi/hUVPBE0wSzElMCMEHmNvbS5leGFtcGxlLnRydXN0ZWRhcHBsaWNhdGlvbgIBATEiBCCI5cOT6u82gpgAtB33hqUv8KWCFYUMqKZQc4Wa3PAZDzA3oQgxBgIBAgIBA6IDAgEDowQCAgEApQgxBgIBAAIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FPwIFADAfBgNVHSMEGDAWgBQ//KzWGrE6noEguNUlHMVlux6RqTAKBggqhkjOPQQDAgNIADBFAiBiMBtVeUV4j1VOiRU8DnGzq9/xtHfl0wra1xnsmxG+LAIhAJAroVhVcxxItgYZEMN1AaWqmZUXFtktQeLXh7u2F3d+",
                    "MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7",
                    "MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw=="
                ),
                isoDate = "2023-09-10T00:00:00Z",
                packageName = "com.example.trustedapplication",
                expectedDigest = "88E5C393EAEF36829800B41DF786A52FF0A58215850CA8A65073859ADCF0190F".hexToByteArray(
                    HexFormat.UpperCase
                ),
                attestationLevel = AttestationData.Level.NOUGAT
            ),
            AttestationData(
                "Nokia X10",
                challengeB64 = "HcAotmy6ZBX8cnh5mvMc2w==",
                attestationProofB64 = listOf(
                    """
                        MIICozCCAkigAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDg4NGY4MTlkYzAxMjJkYjFm
                        NGFiZDI4YzllNzBmM2QwMCAXDTcwMDEwMTAwMDAwMFoYDzIxMDYwMjA3MDYyODE1WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtl
                        eXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC9z3T/NtNDTc94eKdG3MKz4pIg+frP6j1zf3h4pE3fEZ0Ir
                        rXM+LagKuDV4HJoy4hHDSDrZD0youOREwxKKj6SjggFXMIIBUzAOBgNVHQ8BAf8EBAMCB4AwggE/BgorBgEEAdZ5AgERBIIB
                        LzCCASsCAQMKAQECAQQKAQEEEB3AKLZsumQV/HJ4eZrzHNsEADBfv4U9CAIGAYd/5YkQv4VFTwRNMEsxJTAjBB5hdC5hc2l0
                        cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaehCDEGAgEC
                        AgEDogMCAQOjBAICAQClCDEGAgEEAgECqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCDU9Nwdz6RJ5XFKxYBLU0JAfUxps3hH
                        RVc6cnRct9Wb9gEB/woBAAQgJ+BQyXYw7V5iEtU6QFzXeCnCpi75mTof21kND/tR7YC/hUEFAgMB+9C/hUIFAgMDFj+/hU4G
                        AgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNJADBGAiEAmSuuN2StHrBfO3J9tR45vcq/22Gn5cXKXt+DR45MBroCIQCu
                        abv+4ia9Y7w8ooHzql2OVYiDatqR9k5YUPABdVwd1g==
                        """,
                    """
                        MIIB8zCCAXqgAwIBAgIRALdlXIz6RNuRvfQY1AsxwIwwCgYIKoZIzj0EAwIwOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBl
                        MGMzNTQ4YTQ3ZTczZjJhNzVmYjllZDZkYTViZjNlODAeFw0yMDA5MjgyMDE4NDhaFw0zMDA5MjYyMDE4NDhaMDkxDDAKBgNV
                        BAwMA1RFRTEpMCcGA1UEBRMgODg0ZjgxOWRjMDEyMmRiMWY0YWJkMjhjOWU3MGYzZDAwWTATBgcqhkjOPQIBBggqhkjOPQMB
                        BwNCAATmhTTiVhHty0CEC/ZOmZukvtlo0oVljIk/X66yucR13UfkzVzErNuM7Dznj0yGlSylkSTeJOYRUD82AYMQPwJFo2Mw
                        YTAdBgNVHQ4EFgQUPY4E/H/RzXhd1rVjbMikMLz6CLMwHwYDVR0jBBgwFoAUwlMBrj5jAa/ypZzVX4CUjgAyTjwwDwYDVR0T
                        AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDZwAwZAIwCsSg1hhIw9M3OFndg+2OzsCCCtyckDEYeQZL
                        Sc1w+LNAqsxkC6p/yhmgG+jyIDB7AjAyg7gzKF6ymsSQ+C55zoCS+InIaIK8ruz9RE4J7lC6SIvMCMXhmyoelkZ7aWARKaI=
                        """,
                    """
                        MIIDkzCCAXugAwIBAgIQFk/xbbOK0z0ZBF99wwx/zDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZi
                        MDQ1MB4XDTIwMDkyODIwMTc0OVoXDTMwMDkyNjIwMTc0OVowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3
                        ZTczZjJhNzVmYjllZDZkYTViZjNlODB2MBAGByqGSM49AgEGBSuBBAAiA2IABJHz0uU3kbaMjfVN38GXDgIBLl4Gp7P59n6+
                        zmqoswoBrbrsCiFOWUU+B918FnEVcW86joLS+Ysn7msakvrHanJMJ4vDwD7/p+F6nkQ9J95FEkuq71oGTzCrs6SlCHu5XqNj
                        MGEwHQYDVR0OBBYEFMJTAa4+YwGv8qWc1V+AlI4AMk48MB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1Ud
                        EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQAnO5KNrbenSYxIOfzxH47CNi3Qz2O5+FoP
                        W7svNjggg/hZotSwbddpSVa+fdQYYYZdHMPNjQKXYaDxPPC2i/8KBhscq+TW1k9YKP+qNGMZ2CKzRIT0pByL0M5LQNbH6VxA
                        vzGlaCvTOIsDmlLyjzmT9QMtjWkmLKduISOa72hGMM4kCcIRKcgsq/s00whsOJ6IT27lp85AATuL9NvNE+kC1TZ96zEsR8Op
                        lur4euBmFoGzmtSFsZa9TNyc68RuJ+n/bY7iI77wXUz7ER6uj/sfnrjYJFclLjIjm8Mqp69IZ1nbJsKTgg0e5X4xeecNPLSM
                        p/hGqDOvNnSVbpri6Djm0ZWILk65BeRxANDUhICg/iuXnbSLIgPAIxsmniTV41nnIQ2nwDxVtfStsPzSWeEKkMTeta+Lu8jK
                        KVDcRTt2zoGx+JOQWaEWpOTUM/xZwnJamdHsKBWsskQhFMxLIPJbMeYAeCCswDTE+LQv31wDTxSrFVw/fcfVY6PSRZWoy+6Q
                        /zF3JATwQnYxNUchZG4suuy/ONPbOhD0VdzjkSyza6fomTw2F1G3c4jSQIiNV3OIxsxh4ja1ssJqMPuQzRcGGXxX8yQHrg+t
                        +Dxn32jFVhl5bxTeKuI6mWBYM+/qEBTBEXLNSmVdxrntFaPmiQcguBSFR1oHZyi/xS/jbYFZEQ==
                        """,
                    """
                        MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcN
                        MTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
                        AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2
                        tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
                        nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC
                        8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
                        JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8G
                        o3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
                        RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2
                        QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
                        IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEB
                        CwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U
                        h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcp
                        YEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA
                        D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fF
                        hE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91
                        oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw
                        9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH
                        ex0SdDrx+tWUDqG8At2JHA==
                        """
                ),
                isoDate = "2023-04-14T13:12:42Z",
                pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEL3PdP8200NNz3h4p0bcwrPikiD5+s/qPXN/eHikTd8RnQiutcz4tqAq4NXgcmjLiEcNIOtkPTKi45ETDEoqPpA==",
                packageName = "at.asitplus.attestation_client",
                expectedDigest = Base64.decode("NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU=")
            ),
            AttestationData(
                "Pixel 6",
                challengeB64 = "9w11c/H1kgfx+2Lqrqscug==",
                attestationProofB64 = listOf(
                    """
                        MIICpzCCAk6gAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIGQ3MWRmYjM1NjNlNWQ5Y2I0
                        NmRkMTJjMWJhMjI2YzM5MB4XDTIzMDQxNDE0MzAyMVoXDTQ4MDEwMTAwMDAwMFowJTEjMCEGA1UEAxMaaHR0cDovLzE5Mi4x
                        NjguMTc4LjMzOjgwODAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASqzk1wE4o3jS27/n40sW8ZExFxgXopGSxihSaLCUqG
                        HNsZoAvMTY96sQznDM0p4LoRKu5klGgE+4efkP4d+gyQo4IBWTCCAVUwDgYDVR0PAQH/BAQDAgeAMIIBQQYKKwYBBAHWeQIB
                        EQSCATEwggEtAgIAyAoBAQICAMgKAQEEEPcNdXPx9ZIH8fti6q6rHLoEADBfv4U9CAIGAYeALKLxv4VFTwRNMEsxJTAjBB5h
                        dC5hc2l0cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaeh
                        CDEGAgECAgEDogMCAQOjBAICAQClCDEGAgECAgEEqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCAPbnXIAYO13sB0sAVNQnHp
                        k4nr5LE2sIGd4fFQug/51wEB/woBAAQgNidLYFH3o3y3ufJGD1UzB8M0ZzGpxDl7RrvUI0SJSwi/hUEFAgMB+9C/hUIFAgMD
                        Fj+/hU4GAgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNHADBEAiAYJTfwNDCSiw/fob8VIBSNnXfaQaoyLxVmbaP/U5e2
                        AgIgAlngbOcR1syv1RP369hnI8cMh4xe1AFnB+H3Y9OVirQ=
                        """,
                    """
                        MIIBwzCCAWqgAwIBAgIRANcd+zVj5dnLRt0SwboibDkwCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAG
                        A1UEAxMJRHJvaWQgQ0EzMB4XDTIzMDMyNjExNDk0OVoXDTIzMDUwMTExNDk0OVowOTEMMAoGA1UEChMDVEVFMSkwJwYDVQQD
                        EyBkNzFkZmIzNTYzZTVkOWNiNDZkZDEyYzFiYTIyNmMzOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJS3ylJ9AibrkDPP
                        /W4PBHmHU/e+yRiSTr4nLkojZzkBDWayhRI6PhrsN8Cetsp2EG2r2dQ60VnPvtvw9ElYYlGjYzBhMB0GA1UdDgQWBBQRvZZG
                        VqzjrxcT1lU/u8OGt6xJSjAfBgNVHSMEGDAWgBTEfQBQs7lkcRyV+Ok7Vmuti/ra9zAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
                        DwEB/wQEAwICBDAKBggqhkjOPQQDAgNHADBEAiAjV7E60YcWRMdplr3lyh/M6nSHuADoGWdO10hP2h/81gIgTRHSnjjwPA3F
                        GlyYg8DGschrg3a7j8lEzLg2kRmzg9c=
                        """,
                    """
                        MIIB1jCCAVygAwIBAgITKqOs6sgL8zCfdZ1InqRvUR51szAKBggqhkjOPQQDAzApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIw
                        EAYDVQQDEwlEcm9pZCBDQTIwHhcNMjMwMzI3MjMxMzUyWhcNMjMwNTAxMjMxMzUxWjApMRMwEQYDVQQKEwpHb29nbGUgTExD
                        MRIwEAYDVQQDEwlEcm9pZCBDQTMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGyo5Rgphmke9X1N+/0OBQzlUIsfWudjeX
                        WaFQOUl8VKN9y00pYQlyICzNAC4A9/f92tNhF3RkCn//Xfae9zcDo2MwYTAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUw
                        AwEB/zAdBgNVHQ4EFgQUxH0AULO5ZHEclfjpO1ZrrYv62vcwHwYDVR0jBBgwFoAUu/g2rYmubOLlnpTw1bLX0nrkfEEwCgYI
                        KoZIzj0EAwMDaAAwZQIwffCbRJ9FCtNJopq2R2L0cpeoLKZTmu3SD2tcnU1CxBbEnhBA8Jl1giOBPsdB+VrPAjEA74XTlWF8
                        C2UmzwiCRxemo+tlw9EJ752ljAIwlUOWErA40tIGRe18736YdxM/zC8X
                        """,
                    """
                        MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4X
                        DTIyMDEyNjIyNDc1MloXDTM3MDEyMjIyNDc1MlowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0Ey
                        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuppxbZvJgwNXXe6qQKidXqUt1ooT8M6Q+ysWIwpduM2EalST8v/Cy2JN10aqTfUS
                        ThJha/oCtG+F9TUUviOch6RahrpjVyBdhopM9MFDlCfkiCkPCPGu2ODMj7O/bKnko2YwZDAdBgNVHQ4EFgQUu/g2rYmubOLl
                        npTw1bLX0nrkfEEwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8B
                        Af8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAIFxUiFHYfObqrJM0eeXI+kZFT57wBplhq+TEjd+78nIWbKvKGUFlvt7IuXH
                        zZ7YJdtSDs7lFtCsxXdrWEmLckxRDCRcth3Eb1leFespS35NAOd0Hekg8vy2G31OWAe567l6NdLjqytukcF4KAzHIRxoFivN
                        +tlkEJmg7EQw9D2wPq4KpBtug4oJE53R9bLCT5wSVj63hlzEY3hC0NoSAtp0kdthow86UFVzLqxEjR2B1MPCMlyIfoGyBgky
                        AWhd2gWN6pVeQ8RZoO5gfPmQuCsn8m9kv/dclFMWLaOawgS4kyAn9iRi2yYjEAI0VVi7u3XDgBVnowtYAn4gma5q4BdXgbWb
                        UTaMVVVZsepXKUpDpKzEfss6Iw0zx2Gql75zRDsgyuDyNUDzutvDMw8mgJmFkWjlkqkVM2diDZydzmgi8br2sJTLdG4lUwve
                        dIaLgjnIDEG1J8/5xcPVQJFgRf3m5XEZB4hjG3We/49p+JRVQSpE1+QzG0raYpdNsxBUO+41diQo7qC7S8w2J+TMeGdpKGjC
                        IzKjUDAy2+gOmZdZacanFN/03SydbKVHV0b/NYRWMa4VaZbomKON38IH2ep8pdj++nmSIXeWpQE8LnMEdnUFjvDzp0f0ELSX
                        VW2+5xbl+fcqWgmOupmU4+bxNJLtknLo49Bg5w9jNn7T7rkF
                        """,
                    """
                        MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcN
                        MTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
                        AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2
                        tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
                        nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC
                        8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
                        JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8G
                        o3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
                        RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2
                        QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
                        IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEB
                        CwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U
                        h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcp
                        YEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA
                        D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fF
                        hE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91
                        oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw
                        9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH
                        ex0SdDrx+tWUDqG8At2JHA==
                        """
                ),
                isoDate = "2023-04-14T14:31:42Z",
                pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqs5NcBOKN40tu/5+NLFvGRMRcYF6KRksYoUmiwlKhhzbGaALzE2PerEM5wzNKeC6ESruZJRoBPuHn5D+HfoMkA==",
                packageName = "at.asitplus.attestation_client",
                expectedDigest = Base64.decode("NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU=")
            )
        ) {
            val bytes = it.attestationCertChain.first().encoded
            val certParsed = X509Certificate.decodeFromDer(bytes)
            certParsed.encodeToDer() shouldBe bytes
            val attestation = certParsed.androidAttestationExtension
            attestation.shouldNotBeNull()
            val info = attestation.softwareEnforced.attestationApplicationInfo
            info.shouldNotBeNull()
            info.shouldNotBeEmpty()
            info.first().packageName shouldBe it.packageName
            val digests = attestation.softwareEnforced.attestationApplicationDigest
            digests.shouldNotBeNull()
            digests.shouldNotBeEmpty()
            digests.first() shouldBe it.expectedDigest

            //this means that every field that has been parsed is correctly re-encoded into the same generic structure found in the certificate extension
            attestation.encodeToTlv() shouldBe certParsed.tbsCertificate.extensions!!.first { it.oid == AttestationKeyDescription.oid }.value.asEncapsulatingOctetString().children.first()

            //we get the result, so that there's a parsed attestation record in there
            //we don't care for strict attestation checks, only for parsing
            val result = attestationService(
                it.attestationLevel,
                it.packageName,
                listOf(it.expectedDigest)
            ).verifyAttestation(it.attestationCertChain, it.verificationDate, it.challenge)

            //now we compare
            result.softwareEnforced().compareWith(attestation.softwareEnforced)
            result.teeEnforced().compareWith(attestation.hardwareEnforced)
        }
    }
})

fun AuthorizationList.compareWith(signum: at.asitplus.signum.indispensable.pki.attestation.AuthorizationList) {
    this.algorithm().getOrNull()?.let { it.ordinal shouldBe signum.algorithm?.ordinal }
        ?: signum.algorithm.shouldBeNull()
    this.keySize().getOrNull()?.let { it shouldBe signum.keySize!!.intValue.toBigInteger().intValue(true) }
        ?: signum.keySize.shouldBeNull()
    this.digest()?.let {
        if (it.isNotEmpty()) {
            it.forEach { value -> signum.digest!!.find { it.ordinal == value.ordinal } }
        } else signum.digest.shouldBeNull()
    } ?: signum.digest.shouldBeNull()

    this.activeDateTime().getOrNull()
        ?.let { it.toEpochMilli() shouldBe signum.activeDateTime!!.intValue.toBigInteger().longValue(true) }
        ?: signum.activeDateTime.shouldBeNull()

    if (this.allowWhileOnBody()) signum.allowWhileOnBody.shouldNotBeNull() else signum.allowWhileOnBody.shouldBeNull()

    this.attestationApplicationId().getOrNull()?.let { info ->
        signum.attestationApplicationInfo.shouldNotBeNull().let {
            info.packageInfos()?.let { pInfos ->
                pInfos.forEach { pInfo ->
                    it.first { it.packageName == pInfo.packageName() && it.version == pInfo.version().toUInt() }
                }
            }
            info.signatureDigests()?.let { digests ->
                signum.attestationApplicationDigest.shouldNotBeNull().let {
                    digests.forEach { digest -> it.first { digest.toByteArray().contentEquals(it) } }
                }
            }
        } ?: signum.attestationApplicationInfo.shouldBeNull()

    }
    this.attestationIdBrand().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdBrand!!.stringValue.toByteArray())
        ?: signum.attestationIdBrand.shouldBeNull()

    this.attestationIdImei().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdImei!!.stringValue.toByteArray())
        ?: signum.attestationIdImei.shouldBeNull()

    this.attestationIdSecondImei().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdSecondImei!!.stringValue.toByteArray())
        ?: signum.attestationIdSecondImei.shouldBeNull()

    this.attestationIdSerial().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdSerial!!.stringValue.toByteArray())
        ?: signum.attestationIdSerial.shouldBeNull()

    this.attestationIdMeid().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdMeid!!.stringValue.toByteArray())
        ?: signum.attestationIdMeid.shouldBeNull()

    this.attestationIdDevice().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdDevice!!.stringValue.toByteArray())
        ?: signum.attestationIdDevice.shouldBeNull()

    this.attestationIdManufacturer().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdManufacturer!!.stringValue.toByteArray())
        ?: signum.attestationIdManufacturer.shouldBeNull()

    this.attestationIdModel().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdModel!!.stringValue.toByteArray())
        ?: signum.attestationIdModel.shouldBeNull()

    this.attestationIdProduct().getOrNull()?.toByteArray()
        ?.contentEquals(signum.attestationIdProduct!!.stringValue.toByteArray())
        ?: signum.attestationIdProduct.shouldBeNull()


    // Purpose comparison
    this.purpose()?.let {
        if (it.isNotEmpty()) {
            signum.purpose.shouldNotBeNull()
            it.forEach { value -> signum.purpose!!.find { it.ordinal == value.ordinal } }
        } else signum.purpose.shouldBeNull()
    } ?: signum.purpose.shouldBeNull()

    // Padding comparison
    this.padding()?.let {
        if (it.isNotEmpty()) {
            signum.padding.shouldNotBeNull()
            it.forEach { value -> signum.padding!!.find { it.ordinal == value.ordinal } }
        } else signum.padding.shouldBeNull()
    } ?: signum.padding.shouldBeNull()

    // EC Curve comparison
    this.ecCurve().getOrNull()?.let { it.ordinal shouldBe signum.ecCurve?.ordinal }
        ?: signum.ecCurve.shouldBeNull()

    // RSA Public Exponent comparison
    this.rsaPublicExponent().getOrNull()
        ?.let { it shouldBe signum.rsaPublicExponent!!.intValue.toBigInteger().longValue(true) }
        ?: signum.rsaPublicExponent.shouldBeNull()


    // RollbackResistance comparison
    if (this.rollbackResistance()) signum.rollbackResistance.shouldNotBeNull() else signum.rollbackResistance.shouldBeNull()


    // OriginationExpireDateTime comparison
    this.originationExpireDateTime().getOrNull()
        ?.let { it.toEpochMilli() shouldBe signum.originationExpireDateTime!!.intValue.toBigInteger().longValue(true) }
        ?: signum.originationExpireDateTime.shouldBeNull()

    // UsageExpireDateTime comparison
    this.usageExpireDateTime().getOrNull()
        ?.let { it.toEpochMilli() shouldBe signum.usageExpireDateTime!!.intValue.toBigInteger().longValue(true) }
        ?: signum.usageExpireDateTime.shouldBeNull()


    // NoAuthRequired comparison
    if (this.noAuthRequired()) signum.noAuthRequired.shouldNotBeNull() else signum.noAuthRequired.shouldBeNull()

    // UserAuthType comparison
    this.userAuthType().forEach { it.ordinal shouldBe signum.userAuthType!!.intValue.toBigInteger().intValue(true) }

    // AuthTimeout comparison
    this.authTimeout().getOrNull()
        ?.let { it.seconds shouldBe signum.authTimeout!!.intValue.toBigInteger().longValue(true) }
        ?: signum.authTimeout.shouldBeNull()

    // TrustedUserPresenceRequired comparison
    if (this.trustedUserPresenceRequired()) signum.trustedUserPresenceRequired.shouldNotBeNull()
    else signum.trustedUserPresenceRequired.shouldBeNull()

    // TrustedConfirmationRequired comparison
    if (this.trustedConfirmationRequired()) signum.trustedConfirmationRequired.shouldNotBeNull()
    else signum.trustedConfirmationRequired.shouldBeNull()

    // UnlockedDeviceRequired comparison
    if (this.unlockedDeviceRequired()) signum.unlockedDeviceRequired.shouldNotBeNull()
    else signum.unlockedDeviceRequired.shouldBeNull()

    // CreationDateTime comparison
    this.creationDateTime().getOrNull()
        ?.let { it.toEpochMilli() shouldBe signum.creationDateTime!!.intValue.toBigInteger().longValue(true) }
        ?: signum.creationDateTime.shouldBeNull()

    // Origin comparison
    this.origin().getOrNull()?.let { it.ordinal shouldBe signum.origin?.ordinal }
        ?: signum.origin.shouldBeNull()


    // RootOfTrust comparison
    this.rootOfTrust().getOrNull()?.let { root ->
        signum.rootOfTrust.shouldNotBeNull().let {
            root.verifiedBootKey().toByteArray().contentEquals(it.verifiedBootKeyDigest)
            root.deviceLocked() shouldBe it.deviceLocked
            root.verifiedBootState().ordinal shouldBe it.verifiedBootState.ordinal
            root.verifiedBootHash().getOrNull()?.toByteArray()?.contentEquals(it.verifiedBootHash)
                ?: it.verifiedBootHash.shouldBeNull()
        }
    } ?: signum.rootOfTrust.shouldBeNull()

// OsVersion comparison
    this.osVersion().getOrNull()
        ?.let { osVersion ->
            signum.osVersion.shouldNotBeNull()
            osVersion.toInt() shouldBe signum.osVersion.intValue.toBigInteger().intValue(true)
        }
        ?: signum.osVersion.shouldBeNull()

// OsPatchLevel comparison
    this.osPatchLevel().getOrNull()
        ?.let { date ->
            signum.osPatchLevel.shouldNotBeNull()
            // Ensure proper numeric type conversion for comparison
            date.year.toInt() shouldBe signum.osPatchLevel.year.toInt()
            date.monthValue.toInt() shouldBe signum.osPatchLevel.month.ordinal + 1
        }
        ?: signum.osPatchLevel.shouldBeNull()

// VendorPatchLevel comparison
    this.vendorPatchLevel().getOrNull()
        ?.let { date ->
            signum.vendorPatchLevel.shouldNotBeNull()
            // Ensure proper numeric type conversion for comparison
            date.year.toInt() shouldBe signum.vendorPatchLevel.year.toInt()
            date.monthValue.toInt() shouldBe signum.vendorPatchLevel.month.ordinal + 1
            date.dayOfMonth.toInt() shouldBe signum.vendorPatchLevel.day.toInt()
        }
        ?: signum.vendorPatchLevel.shouldBeNull()

// BootPatchLevel comparison
    this.bootPatchLevel().getOrNull()
        ?.let { date ->
            signum.bootPatchLevel.shouldNotBeNull()
            // Ensure proper numeric type conversion for comparison
            date.year.toInt() shouldBe signum.bootPatchLevel.year.toInt()
            date.monthValue.toInt() shouldBe signum.bootPatchLevel.month.ordinal + 1
            date.dayOfMonth.toInt() shouldBe signum.bootPatchLevel.day.toInt()
        }
        ?: signum.bootPatchLevel.shouldBeNull()


}


fun attestationService(
    attestationLevel: Level,
    androidPackageName: String,
    androidAppSignatureDigest: List<ByteArray>,
    androidVersion: Int? = null,
    androidAppVersion: Int? = null,
    androidPatchLevel: PatchLevel? = null,
    requireStrongBox: Boolean = false,
    unlockedBootloaderAllowed: Boolean = false,
    requireRollbackResistance: Boolean = false,
    attestationStatementValiditiy: Duration = 5.minutes
) = when (attestationLevel) {
    Level.HARDWARE -> HardwareAttestationChecker(
        AndroidAttestationConfiguration(
            listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = androidPackageName,
                    signatureDigests = androidAppSignatureDigest,
                    appVersion = androidAppVersion
                )
            ),
            androidVersion = androidVersion,
            patchLevel = androidPatchLevel,
            requireStrongBox = requireStrongBox,
            allowBootloaderUnlock = unlockedBootloaderAllowed,
            requireRollbackResistance = requireRollbackResistance,
            attestationStatementValiditySeconds = attestationStatementValiditiy.inWholeSeconds.toInt(),
            ignoreLeafValidity = true
        )
    )

    Level.SOFTWARE -> SoftwareAttestationChecker(
        AndroidAttestationConfiguration(
            listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = androidPackageName,
                    signatureDigests = androidAppSignatureDigest,
                    appVersion = androidAppVersion
                )
            ),
            disableHardwareAttestation = true,
            enableSoftwareAttestation = true,
            androidVersion = androidVersion,
            patchLevel = androidPatchLevel,
            requireStrongBox = requireStrongBox,
            allowBootloaderUnlock = unlockedBootloaderAllowed,
            requireRollbackResistance = requireRollbackResistance,
            attestationStatementValiditySeconds = attestationStatementValiditiy.inWholeSeconds.toInt(),
            ignoreLeafValidity = true
        )
    )

    Level.NOUGAT -> NougatHybridAttestationChecker(
        AndroidAttestationConfiguration(
            listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = androidPackageName,
                    signatureDigests = androidAppSignatureDigest,
                    appVersion = androidAppVersion
                )
            ),
            disableHardwareAttestation = true,
            enableNougatAttestation = true,
            androidVersion = androidVersion,
            patchLevel = androidPatchLevel,
            requireStrongBox = requireStrongBox,
            allowBootloaderUnlock = unlockedBootloaderAllowed,
            requireRollbackResistance = requireRollbackResistance,
            attestationStatementValiditySeconds = attestationStatementValiditiy.inWholeSeconds.toInt(),
            ignoreLeafValidity = true
        )
    )
}