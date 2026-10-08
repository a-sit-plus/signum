package at.asitplus.signum.examples

import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.encodeToByteArray
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlin.time.Instant

val CoseExamples by matrixSuite {
    Signum.installSupreme()
    "COSE Sign1 signs the protected header, payload and external AAD" {
        // --8<-- [start:cose-sign-verify]
        val signer = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1 } }
        val protected = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256, kid = "binding-key".encodeToByteArray())
        val payload = "hello".encodeToByteArray()
        val aad = "application context".encodeToByteArray()
        val input = CoseSigned.prepare(protectedHeader = protected, payload = payload,
            externalAad = aad, payloadSerializer = ByteArraySerializer())
        val signed = CoseSigned.create(protectedHeader = protected, payload = payload,
            signature = signer.sign(coseCompliantSerializer.encodeToByteArray(input)).signature, payloadSerializer = ByteArraySerializer())
        val received = CoseSigned.deserialize(ByteArraySerializer(), signed.serialize(ByteArraySerializer())).getOrThrow()
        require(received.protectedHeader.algorithm == CoseAlgorithm.Signature.ES256)
        val verifier = signer.makeVerifier() /* (1)! */
        verifier.verify(received.prepareCoseSignatureInput(aad), received.signature) shouldBe SignatureVerifier.Success
        runCatching { verifier.verify(received.prepareCoseSignatureInput(), received.signature) }.isFailure shouldBe true
        // --8<-- [end:cose-sign-verify]
    }
    "CWT serialization" {
        // --8<-- [start:cose-cwt]
        val claims = CborWebToken(issuer = "https://issuer.example", subject = "alice",
            audience = "example-service", expiration = Instant.parse("2030-01-01T00:00:00Z"))
        val decoded = CborWebToken.deserialize(claims.serialize()).getOrThrow()
        decoded shouldBe claims
        require(Instant.parse("2027-01-01T00:00:00Z") < requireNotNull(decoded.expiration))
        // --8<-- [end:cose-cwt]
    }
}
