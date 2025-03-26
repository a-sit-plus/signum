@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.bouncycastle.util.encoders.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class BasicParsingTests : FreeSpec({

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
    """ {
        val bytes = Base64.decode(testCase.name.testName)
        val certParsed = X509Certificate.decodeFromDer(bytes)
        certParsed.encodeToDer() shouldBe bytes
        val attestation= certParsed.androidAttestationExtension
        attestation.shouldNotBeNull()
        val info = attestation.softwareEnforced.attestationApplicationInfo
        info.shouldNotBeNull()
        info.shouldNotBeEmpty()
        info.first().packageName shouldBe "at.asitplus.atttest"
        val digests =attestation.softwareEnforced.attestationApplicationDigest
        digests.shouldNotBeNull()
        digests.shouldNotBeEmpty()
        digests.first() shouldBe Base64.decode("NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU=")
    }
})