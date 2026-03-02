package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.invoke
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.crypto.ECDSAVerifier
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.security.interfaces.ECPublicKey

val JwsGeneralJvmTest by testSuite {

    "general JWS can be created from signed JWS objects and verified" {
        val payload = buildJsonObject {
            put("iss", JsonPrimitive("https://issuer.example"))
            put("sub", JsonPrimitive("alice"))
            put("iat", JsonPrimitive(1_710_000_000))
        }

        val signer1 = Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()

        val signer2 = Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()

        val jws1 = run {
            val header = JwsHeader(
                algorithm = signer1.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                keyId = "kid-1",
            )
            val plainSignatureInput = JwsSigned.prepareJwsSignatureInput(
                header = header,
                payload = payload,
                serializer = JsonObject.serializer(),
                json = joseCompliantSerializer,
            )
            val signature = signer1.sign(plainSignatureInput).signature
            JwsSigned(header, payload, signature, plainSignatureInput)
        }

        val jws2 = run {
            val header = JwsHeader(
                algorithm = signer2.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                keyId = "kid-2",
            )
            val plainSignatureInput = JwsSigned.prepareJwsSignatureInput(
                header = header,
                payload = payload,
                serializer = JsonObject.serializer(),
                json = joseCompliantSerializer,
            )
            val signature = signer2.sign(plainSignatureInput).signature
            JwsSigned(header, payload, signature, plainSignatureInput)
        }

        val general = JwsGeneral.fromSignedJws(jws1, jws2)
        val serialized = joseCompliantSerializer.encodeToString(general)

        val parsed = JWSObjectJSON.parse(serialized)
        parsed.signatures.size shouldBe 2

        val verifierByKid: Map<String, ECDSAVerifier> = mapOf(
            "kid-1" to ECDSAVerifier(signer1.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey),
            "kid-2" to ECDSAVerifier(signer2.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey),
        )

        parsed.signatures.forEach {
            val keyId = it.header.keyID
            val verifier = verifierByKid[keyId]
                ?: throw IllegalStateException("Missing verifier for key id '$keyId'")
            it.verify(verifier).shouldBeTrue()
        }
    }
}
