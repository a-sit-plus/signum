package at.asitplus.signum.examples

import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC7519
import kotlin.time.Instant

// --8<-- [start:jose-jwt-payload-model]
@Serializable
data class AccessClaims(
    @SerialName(RFC7519.ISS) override val issuer: String? = null,
    @SerialName(RFC7519.SUB) override val subject: String? = null,
    @SerialName(RFC7519.AUD) override val audience: String? = null,
    @SerialName(RFC7519.NBF) @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,
    @SerialName(RFC7519.IAT) @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant? = null,
    @SerialName(RFC7519.EXP) @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant? = null,
    @SerialName(RFC7519.JTI) override val jwtId: String? = null,
) : JwtPayload

fun AccessClaims.acceptedByExampleService(now: Instant): Boolean =
    issuer == "https://issuer.example" && audience == "example-service" &&
        !subject.isNullOrBlank() && notBefore?.let { now >= it } == true &&
        expiration?.let { now < it } == true
// --8<-- [end:jose-jwt-payload-model]

val JoseExamples by matrixSuite {
    Signum.installSupreme()
    "JWK and compact JWS with an explicitly trusted key" {
        // --8<-- [start:jose-jws-sign-verify]
        // --8<-- [start:jose-jwk]
        val signer = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1 } }
        val jwk = signer.publicKey.toJsonWebKey(keyId = "binding-key")
        val json = joseCompliantSerializer.encodeToString(JsonWebKey.serializer(), jwk)
        val parsedKey = joseCompliantSerializer.decodeFromString(JsonWebKey.serializer(), json)
        parsedKey.toCryptoPublicKey().getOrThrow() shouldBe signer.publicKey
        // --8<-- [end:jose-jwk]
        val trustedKeys = mapOf("binding-key" to signer.publicKey) /* (1)! */
        val jws = JwsCompact(
            protectedHeader = JwsHeader(algorithm = JwsAlgorithm.Signature.ES256, keyId = "binding-key"),
            payload = "hello".encodeToByteArray(),
        ) { input -> signer.sign(input).signature.joseBytes }
        val received = JwsCompact(jws.toString())
        require(received.jwsHeader.algorithm == JwsAlgorithm.Signature.ES256)
        val trustedKey = requireNotNull(trustedKeys[received.jwsHeader.keyId])
        val verifier = signer.signatureAlgorithm.verifierFor(trustedKey)
        verifier.verify(received.signatureInput, received.signature) shouldBe SignatureVerifier.Success
        received.plainPayload.decodeToString() shouldBe "hello"
        runCatching { verifier.verify("changed".encodeToByteArray(), received.signature) }.isFailure shouldBe true
        // --8<-- [end:jose-jws-sign-verify]
    }
    "JWT claims remain application policy" {
        // --8<-- [start:jose-jwt]
        val claims = buildJsonObject {
            put("iss", "https://issuer.example")
            put("sub", "alice")
            put("aud", "example-service")
            put("exp", 1893456000L)
        }
        val signer = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1 } }
        val jwt: JwsCompactTyped<JsonObject> = JwsTyped(
            protectedHeader = JwsHeader(algorithm = JwsAlgorithm.Signature.ES256, type = "JWT"),
            payload = claims,
        ) { input -> signer.sign(input).signature.joseBytes }
        val received = JwsTyped<JsonObject>(jwt.toString())
        signer.makeVerifier().verify(received.jws.signatureInput, received.jws.signature) shouldBe SignatureVerifier.Success
        val decoded = received.payload
        decoded["aud"]?.jsonPrimitive?.content shouldBe "example-service"
        require(1798761600L < requireNotNull(decoded["exp"]).jsonPrimitive.long) /* (1)! */
        // --8<-- [end:jose-jwt]
    }
    "typed JwtPayload preserves claim names and enforces example policy" {
        // --8<-- [start:jose-jwt-typed-claims]
        val now = Instant.parse("2027-01-01T00:00:00Z")
        val claims = AccessClaims(issuer = "https://issuer.example", subject = "alice",
            audience = "example-service", notBefore = now, issuedAt = now,
            expiration = Instant.parse("2027-01-01T01:00:00Z"), jwtId = "request-1")
        val signer = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1 } }
        val jwt: JwsCompactTyped<AccessClaims> = JwsTyped(
            protectedHeader = JwsHeader(algorithm = JwsAlgorithm.Signature.ES256, type = "JWT"),
            payload = claims,
        ) { input -> signer.sign(input).signature.joseBytes }
        val received = JwsTyped<AccessClaims>(jwt.toString())
        signer.makeVerifier().verify(received.jws.signatureInput, received.jws.signature) shouldBe SignatureVerifier.Success
        received.payload shouldBe claims
        val json = joseCompliantSerializer.decodeFromString<JsonObject>(received.jws.plainPayload.decodeToString())
        json[RFC7519.ISS]?.jsonPrimitive?.content shouldBe claims.issuer
        json[RFC7519.EXP]?.jsonPrimitive?.long shouldBe claims.expiration?.epochSeconds
        received.payload.acceptedByExampleService(now) shouldBe true /* (1)! */
        claims.copy(audience = "another-service").acceptedByExampleService(now) shouldBe false
        claims.copy(notBefore = claims.expiration).acceptedByExampleService(now) shouldBe false
        claims.acceptedByExampleService(requireNotNull(claims.expiration)) shouldBe false
        // --8<-- [end:jose-jwt-typed-claims]
    }

}
