package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Instant

val KeyAttestationJwtTest by testSuite {
    "KeyAttestationJwt roundtrips through ExperimentalKeyAtt" {
        val keyJson = """
            {
              "kty": "EC",
              "use": "sig",
              "crv": "P-256",
              "x": "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
              "y": "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
            }
        """.trimIndent()
        val original = KeyAttestationJwt(
            issuer = "https://issuer.example.com",
            subject = "wallet-instance",
            issuedAt = Instant.fromEpochSeconds(1710000000),
            attestedKeys = listOf(joseCompliantSerializer.decodeFromString(keyJson)),
            keyStorage = listOf("secure_element"),
            userAuthentication = listOf("local_user_authentication"),
            certification = "https://example.com/certification",
        )
        val serialized = joseCompliantSerializer.encodeToString(original)
        val experimental = joseCompliantSerializer.decodeFromString<ExperimentalKeyAtt>(serialized)
        val roundTripped = joseCompliantSerializer.decodeFromString<KeyAttestationJwt>(
            joseCompliantSerializer.encodeToString(experimental)
        )

        roundTripped shouldBe original
    }
}
