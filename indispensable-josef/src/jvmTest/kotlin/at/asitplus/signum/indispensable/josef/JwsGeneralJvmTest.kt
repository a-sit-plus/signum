package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.crypto.ECDSAVerifier
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.equals.shouldBeEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.security.interfaces.ECPublicKey

val JwsGeneralJvmTest by testSuite {

    class Context {
        val payloadAlice = buildJsonObject {
            put("iss", JsonPrimitive("https://issuer.example"))
            put("sub", JsonPrimitive("alice"))
            put("iat", JsonPrimitive(1_710_000_000))
        }

        val payloadBob = buildJsonObject {
            put("iss", JsonPrimitive("https://issuer.example"))
            put("sub", JsonPrimitive("bob"))
            put("iat", JsonPrimitive(1_710_000_001))
        }

        val signer1 = Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()

        val signer2 = Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()

        val signer3 = Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()

        val verifierByKid: Map<String, ECDSAVerifier> = mapOf(
            "kid-1" to ECDSAVerifier(signer1.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey),
            "kid-2" to ECDSAVerifier(signer2.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey),
            "kid-3" to ECDSAVerifier(signer3.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey),
        )
    }

    suspend fun createSignedJws(
        signer: Signer,
        payload: JsonObject,
        keyId: String,
    ): JwsSigned<JsonObject> {
        val header = JwsHeader(
            algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            keyId = keyId,
        )
        val plainSignatureInput = JwsSigned.prepareJwsSignatureInput(
            header = header,
            payload = payload,
            serializer = JsonObject.serializer(),
            json = joseCompliantSerializer,
        )
        val signature = signer.sign(plainSignatureInput).signature
        return JwsSigned(header, payload, signature, plainSignatureInput)
    }

    withFixtureGenerator(::Context) - {

        "general JWS can be created from signed JWS objects and verified" { it ->
            val jws1 = createSignedJws(it.signer1, it.payloadAlice, "kid-1")
            val jws2 = createSignedJws(it.signer2, it.payloadAlice, "kid-2")

            val general = JwsGeneral.fromSignedJws(jws1, jws2)
            val serialized = joseCompliantSerializer.encodeToString(general)

            val parsed = JWSObjectJSON.parse(serialized)
            parsed.signatures.size shouldBe 2

            parsed.signatures.forEach { signature ->
                val keyId = signature.header.keyID
                val verifier = it.verifierByKid[keyId]
                    ?: throw IllegalStateException("Missing verifier for key id '$keyId'")
                signature.verify(verifier).shouldBeTrue()
            }
        }

        "general JWS can be extended with another signature" { it ->
            val general = JwsGeneral.fromSignedJws(
                createSignedJws(it.signer1, it.payloadBob, "kid-1"),
                createSignedJws(it.signer2, it.payloadBob, "kid-2"),
            )
            val extended = general.appendSignature(createSignedJws(it.signer3, it.payloadBob, "kid-3"))

            general.signatures.size shouldBe 2
            extended.signatures.size shouldBe 3

            val serialized = joseCompliantSerializer.encodeToString(extended)
            val parsed = JWSObjectJSON.parse(serialized)
            parsed.signatures.size shouldBe 3

            parsed.signatures.forEach { signature ->
                val keyId = signature.header.keyID
                val verifier = it.verifierByKid[keyId]
                    ?: throw IllegalStateException("Missing verifier for key id '$keyId'")
                signature.verify(verifier).shouldBeTrue()
            }
        }

        "JwsSigned round-trip" { it ->
            val first = createSignedJws(it.signer1, it.payloadBob, "kid-1")
            val roundtrip = JwsSigned.fromJwsGeneral(JwsGeneral.fromSignedJws(first), 0)
            roundtrip shouldBeEqual first
        }

        "adding signatures with different payloads fails" { it ->
            val general = JwsGeneral.fromSignedJws(
                createSignedJws(it.signer1, it.payloadAlice, "kid-1"),
            )
            val signatureWithDifferentPayload = createSignedJws(it.signer2, it.payloadBob, "kid-2")

            val result = runCatching { general.appendSignature(signatureWithDifferentPayload) }

            result.isSuccess shouldBe false
            result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
            result.exceptionOrNull()?.message?.shouldContain("payload")
        }
    }
}
