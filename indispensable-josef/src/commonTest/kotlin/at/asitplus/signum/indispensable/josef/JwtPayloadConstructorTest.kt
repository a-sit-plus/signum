package at.asitplus.signum.indispensable.josef

import at.asitplus.propigator.json.jsonProperty
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.jwtpayload.ClientAttestationPayload
import at.asitplus.signum.indispensable.josef.jwtpayload.ClientAttestationPopPayload
import at.asitplus.signum.indispensable.josef.jwtpayload.ClientStatus
import at.asitplus.signum.indispensable.josef.jwtpayload.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.jwtpayload.KeyAttestationClaims
import at.asitplus.signum.indispensable.josef.jwtpayload.KeyAttestationPayload
import at.asitplus.signum.indispensable.josef.jwtpayload.KeyStorageStatus
import at.asitplus.signum.indispensable.josef.jwtpayload.WalletAttestationClaims
import at.asitplus.signum.indispensable.josef.jwtpayload.WalletAttestationPayload
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.time.Instant

val JwtPayloadConstructorTest by testSuite {
    "client attestation constructor combines base, confirmation, and misc claims" {
        val payload = ClientAttestationPayload(jwtBaseClaims, confirmationClaim, miscClaims)
        val encoded = payload.encodedJsonObject()

        payload.jwtBaseClaims.shouldContainJwtBaseClaims()
        payload.confirmationClaim shouldBe confirmationClaim
        encoded["cnf"]!!.jsonObject["kid"] shouldBe JsonPrimitive("proof-key")
        encoded["custom_claim"] shouldBe JsonPrimitive("custom-value")
    }

    "client attestation proof of possession constructor combines base, challenge, and misc claims" {
        val payload = ClientAttestationPopPayload(jwtBaseClaims, "challenge-value", miscClaims)
        val encoded = payload.encodedJsonObject()

        payload.jwtBaseClaims.shouldContainJwtBaseClaims()
        payload.challenge shouldBe "challenge-value"
        encoded["challenge"] shouldBe JsonPrimitive("challenge-value")
        encoded["custom_claim"] shouldBe JsonPrimitive("custom-value")
    }

    "key attestation constructor combines base, key attestation, and misc claims" {
        val payload = KeyAttestationPayload(jwtBaseClaims, keyAttestationClaims, miscClaims)

        payload.jwtBaseClaims.shouldContainJwtBaseClaims()
        payload.keyAttestationClaims shouldBe keyAttestationClaims
        payload.encodedJsonObject()["custom_claim"] shouldBe JsonPrimitive("custom-value")
    }

    "key attestation payload can be extended with misc-backed claims" {
        val payload = KeyAttestationPayload(
            jwtBaseClaims,
            keyAttestationClaims,
            JsonObject(mapOf("foo" to JsonPrimitive("foo-value"))),
        )

        payload.foo() shouldBe "foo-value"
    }

    "wallet attestation constructor combines base, wallet attestation, and misc claims" {
        val payload = WalletAttestationPayload(jwtBaseClaims, walletAttestationClaims, miscClaims)

        payload.jwtBaseClaims.shouldContainJwtBaseClaims()
        payload.walletAttestationClaims shouldBe walletAttestationClaims
        payload.encodedJsonObject()["custom_claim"] shouldBe JsonPrimitive("custom-value")
    }

    "constructors reject duplicated claims across constructor parts" {
        runCatching {
            ClientAttestationPayload(
                jwtBaseClaims,
                confirmationClaim,
                JsonObject(mapOf("sub" to JsonPrimitive("override"))),
            )
        }.shouldHaveDuplicateKey("sub")

        runCatching {
            ClientAttestationPopPayload(
                jwtBaseClaims,
                "challenge-value",
                JsonObject(mapOf("challenge" to JsonPrimitive("override"))),
            )
        }.shouldHaveDuplicateKey("challenge")

        runCatching {
            KeyAttestationPayload(
                jwtBaseClaims,
                keyAttestationClaims,
                JsonObject(mapOf("attested_keys" to JsonPrimitive("override"))),
            )
        }.shouldHaveDuplicateKey("attested_keys")

        runCatching {
            WalletAttestationPayload(
                jwtBaseClaims,
                walletAttestationClaims,
                JsonObject(mapOf("wallet_name" to JsonPrimitive("override"))),
            )
        }.shouldHaveDuplicateKey("wallet_name")
    }
}

private val jwtBaseClaims = JwtBaseClaims(
    issuer = "https://issuer.example",
    subject = "client-id",
    audience = "https://verifier.example",
    issuedAt = Instant.fromEpochSeconds(1_700_000_000),
    expiration = Instant.fromEpochSeconds(1_700_003_600),
    jwtId = "jwt-id",
)

private val confirmationClaim = ConfirmationClaim(keyId = "proof-key")

private val miscClaims = JsonObject(
    mapOf(
        "custom_claim" to JsonPrimitive("custom-value"),
    )
)

private val keyStorageStatus = KeyStorageStatus(
    status = JsonObject(
        mapOf(
            "status_list" to JsonObject(
                mapOf(
                    "idx" to JsonPrimitive(42),
                    "uri" to JsonPrimitive("https://example.com/status/key-storage"),
                )
            ),
        )
    ),
    expiration = Instant.fromEpochSeconds(1_700_086_400),
)

private val keyAttestationClaims = KeyAttestationClaims(
    attestedKeys = listOf(JsonWebKey(type = JwkType.EC, keyId = "attested-key")),
    certification = "https://example.com/key-storage/certification",
    keyStorageStatus = keyStorageStatus,
    nonce = "nonce-value",
)

private val clientStatus = ClientStatus(
    status = JsonObject(
        mapOf(
            "status_list" to JsonObject(
                mapOf(
                    "idx" to JsonPrimitive(7),
                    "uri" to JsonPrimitive("https://example.com/status/wallet"),
                )
            ),
        )
    ),
    expiration = Instant.fromEpochSeconds(1_700_086_400),
)

private val walletAttestationClaims = WalletAttestationClaims(
    walletName = "Example Wallet",
    walletLink = "https://example.com/wallet",
    walletVersion = "1.2.3",
    walletSolutionCertificationInformation = "https://example.com/wallet/certification",
    clientStatus = clientStatus,
    confirmationClaim = confirmationClaim,
)

private inline fun <reified T> T.encodedJsonObject(): JsonObject =
    joseCompliantSerializer.encodeToJsonElement(this).jsonObject

private val KeyAttestationPayload.fooClaim: String by jsonProperty("foo")

private fun KeyAttestationPayload.foo(): String = fooClaim

private fun JwtBaseClaims.shouldContainJwtBaseClaims() {
    issuer shouldBe jwtBaseClaims.issuer
    subject shouldBe jwtBaseClaims.subject
    audience shouldBe jwtBaseClaims.audience
    issuedAt shouldBe jwtBaseClaims.issuedAt
    expiration shouldBe jwtBaseClaims.expiration
    jwtId shouldBe jwtBaseClaims.jwtId
}

private fun Result<*>.shouldHaveDuplicateKey(key: String) {
    shouldBeFailure().message.orEmpty().shouldContain("Duplicate keys: $key")
}
