package at.asitplus.signum.indispensable.josef

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

val WalletAttestationJwtTest by testSuite {

    // https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
    "Wallet Instance Attestation"  {
        val input = """
            {
              "sub": "https://client.example.com",
              "iat": 1300815780,
              "exp": 1300902179,
              "wallet_name": "Wallet Solution X by Wonderland State Department",
              "wallet_version": "1.2.3",
              "wallet_link": "https://example.com/wallet/detail_info.html",
              "wallet_solution_certification_information": "https://example.com/wallet/certification.html",
              "client_status": {
                "status": {
                  "status_list": {
                    "idx": 42,
                    "uri": "https://example.com/status/wallet-instance"
                  }
                },
                "exp": 1303494180
              },
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

        parsed.issuer.shouldBeNull()
        parsed.walletName shouldBe "Wallet Solution X by Wonderland State Department"
        parsed.walletVersion shouldBe "1.2.3"
        parsed.walletLink shouldBe "https://example.com/wallet/detail_info.html"
        parsed.walletSolutionCertificationInformation shouldBe "https://example.com/wallet/certification.html"
        parsed.clientStatus.shouldNotBeNull()
        parsed.confirmationClaim.shouldNotBeNull()

        Json.decodeFromString<JsonWebToken>(Json.encodeToString(parsed)) shouldBe parsed
    }
}
