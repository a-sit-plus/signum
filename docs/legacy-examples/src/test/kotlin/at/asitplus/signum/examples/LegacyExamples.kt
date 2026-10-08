package at.asitplus.signum.examples

// --8<-- [start:legacy-imports]
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.supreme.sign.*
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.signature
// --8<-- [end:legacy-imports]
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlin.test.*

class LegacyExamples {
    @Test fun signingResult() {
        // --8<-- [start:legacy-signing-result]
        val failure = SignatureResult.FromException(IllegalStateException("Failed"))
        assertIs<SignatureResult.Error>(failure)
        assertEquals("Failed", failure.exception.message)
        // --8<-- [end:legacy-signing-result]
    }

    @Test fun signing() = runBlocking {
        // --8<-- [start:legacy-signing]
        val key = EphemeralKey { ec { curve = ECCurve.SECP_256_R_1 } }.getOrThrow()
        val signer = key.signer().getOrThrow()
        val data = "Migration".encodeToByteArray()
        val signature = signer.sign(data).signature
        val verifier = signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow()
        assertEquals(Verifier.Success, verifier.verify(data, signature).getOrThrow())
        assertTrue(verifier.verify("Changed".encodeToByteArray(), signature).isFailure)
        // --8<-- [end:legacy-signing]
    }

    @Test fun encoding() = runBlocking {
        // --8<-- [start:legacy-encoding]
        val signer = Signer.Ephemeral { ec {} }.getOrThrow()
        val bytes = signer.publicKey.encodeToDer()
        val decoded = CryptoPublicKey.decodeFromDer(bytes)
        assertEquals(signer.publicKey, decoded)
        assertContentEquals(bytes, decoded.encodeToDer())
        // --8<-- [end:legacy-encoding]
    }

    @Test fun jws() = runBlocking {
        // --8<-- [start:legacy-jws]
        val signer = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1 } }.getOrThrow()
        val message = JwsCompact(JwsHeader(algorithm = JwsAlgorithm.Signature.ES256), "payload".encodeToByteArray()) {
            signer.sign(it).signature.rawByteArray
        }
        val parsed = JwsCompact(message.toString())
        val verifier = signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow()
        assertEquals(Verifier.Success, verifier.verify(parsed.signatureInput, parsed.signature).getOrThrow())
        assertContentEquals("payload".encodeToByteArray(), parsed.plainPayload)
        // --8<-- [end:legacy-jws]
    }

    @Test fun cose() = runBlocking {
        // --8<-- [start:legacy-cose]
        val signer = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1 } }.getOrThrow()
        val header = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256)
        val payload = "payload".encodeToByteArray()
        val input = CoseSigned.prepare(header, payload = payload, payloadSerializer = ByteArraySerializer()).serialize()
        val signature = signer.sign(input).signature
        val message = CoseSigned.create(header, payload = payload, signature = signature, payloadSerializer = ByteArraySerializer())
        val parsed = CoseSigned.deserialize(ByteArraySerializer(), message.serialize(ByteArraySerializer())).getOrThrow()
        val verifier = signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow()
        assertEquals(Verifier.Success, verifier.verify(parsed.prepareCoseSignatureInput(), parsed.signature).getOrThrow())
        assertContentEquals(payload, parsed.payload)
        // --8<-- [end:legacy-cose]
    }
}
