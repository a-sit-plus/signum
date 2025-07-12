package at.asitplus.signum.indispensable.josef

import at.asitplus.test.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class WalletAttestationJwtTest : FreeSpec({

    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-wallet-attestations-in-jwt-
    "Wallet Instance Attestation" - {
        val input = """
            {
              "iss": "https://client.example.com",
              "sub": "https://client.example.com",
              "wallet_name": "Wallet Solution X by Wonderland State Department",
              "wallet_link": "https://example.com/wallet/detail_info.html",
              "nbf": 1300815780,
              "exp": 1300819380,
              "cnf": {
                "jwk": {
                  "kty": "EC",
                  "use": "sig",
                  "crv": "P-256",
                  "x": "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
                  "y": "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
                }
              }
            }
        """.trimIndent()

        val parsed: JsonWebToken = Json.decodeFromString(input)

        parsed.walletName shouldBe "Wallet Solution X by Wonderland State Department"
        parsed.walletLink shouldBe "https://example.com/wallet/detail_info.html"
        parsed.confirmationClaim.shouldNotBeNull()

        Json.decodeFromString<JsonWebToken>(Json.encodeToString(parsed)) shouldBe parsed
    }

})