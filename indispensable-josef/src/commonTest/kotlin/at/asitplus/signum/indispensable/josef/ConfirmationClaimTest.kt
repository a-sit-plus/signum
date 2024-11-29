package at.asitplus.signum.indispensable.josef

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class ConfirmationClaimTest : FreeSpec({

    // https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html#name-wallet-attestation-schema
    "Wallet Instance Attestation" - {
        val input = """
            {
              "iss": "<identifier of the issuer of this wallet attestation>",
              "sub": "<client_id of the OAuth client>",
              "iat": 1516247022,
              "exp": 1541493724,
              "aal" : "https://trust-list.eu/aal/high",
              "cnf": {
                "jwk": {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                  "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
                },
                "key_type": "strong_box",
                "user_authentication": "system_pin"
              }
            }
        """.trimIndent()

        val parsed: JsonWebToken = Json.decodeFromString(input)

        parsed.authenticationLevel shouldBe "https://trust-list.eu/aal/high"
        parsed.confirmationClaim?.keyType shouldBe WalletAttestationKeyType.STRONG_BOX
        parsed.confirmationClaim?.userAuthentication shouldBe WalletAttestationUserAuthentication.SYSTEM_PIN

        val reparsed = Json.decodeFromString<JsonWebToken>(Json.encodeToString(parsed))

        reparsed shouldBe parsed
    }

})