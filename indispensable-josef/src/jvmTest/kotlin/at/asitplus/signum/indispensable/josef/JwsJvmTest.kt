package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.crypto.ECDSAVerifier
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import java.security.interfaces.ECPublicKey

val JwsJvmTest by testSuite {

    class Context {
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()

        val signer1 = Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()

        val signer2 = Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()

        val verifier1 = ECDSAVerifier(signer1.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey)
        val verifier2 = ECDSAVerifier(signer2.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey)

        fun signerFor(signer: Signer): (JwsAlgorithm, ByteArray) -> ByteArray = { _, input ->
            runBlocking { signer.sign(input).signature.rawByteArray }
        }
    }

    withFixtureGenerator(::Context) - {

        "compact JWS can be encoded and verified by Nimbus" { it ->
            val compact = JwsCompact.invoke(
                protectedHeader = JwsHeader.Part(
                    algorithm = it.signer1.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                    keyId = "kid-1",
                    type = "application/example+jws",
                ),
                payload = it.payload,
                signer = it.signerFor(it.signer1),
            )

            val serialized = compact.toString()
            val parsed = JWSObject.parse(serialized)

            parsed.verify(it.verifier1).shouldBeTrue()
            parsed.header.keyID shouldBe "kid-1"
            compact.jwsHeader shouldBe JwsHeader.fromParts(compact.plainProtectedHeader, null)
        }

        "flattened JWS can be serialized and verified by Nimbus" { it ->
            val flattened = JwsFlattened.invoke(
                protectedHeader = JwsHeader.Part(
                    algorithm = it.signer1.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                    type = "application/example+jws",
                ),
                unprotectedHeader = JwsHeader.Part(keyId = "kid-1"),
                payload = it.payload,
                signer = it.signerFor(it.signer1),
            )

            val serialized = joseCompliantSerializer.encodeToString(JwsFlattened.serializer(), flattened)
            val parsed = JWSObjectJSON.parse(serialized)

            parsed.signatures.size shouldBe 1
            parsed.signatures.single().verify(it.verifier1).shouldBeTrue()
            parsed.signatures.single().header.keyID shouldBe null
            parsed.signatures.single().unprotectedHeader.keyID shouldBe "kid-1"
            flattened.jwsHeader shouldBe JwsHeader.fromParts(
                flattened.plainProtectedHeader,
                flattened.unprotectedHeader
            )
        }

        "general JWS can be serialized and verified by Nimbus" { it ->
            val flattened1 = JwsFlattened.invoke(
                protectedHeader = JwsHeader.Part(
                    algorithm = it.signer1.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                ),
                unprotectedHeader = JwsHeader.Part(keyId = "kid-1"),
                payload = it.payload,
                signer = it.signerFor(it.signer1),
            )
            val flattened2 = JwsFlattened.invoke(
                protectedHeader = JwsHeader.Part(
                    algorithm = it.signer2.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                ),
                unprotectedHeader = JwsHeader.Part(keyId = "kid-2"),
                payload = it.payload,
                signer = it.signerFor(it.signer2),
            )

            val general = JwsGeneral.invoke(listOf(flattened1, flattened2))
            val serialized = joseCompliantSerializer.encodeToString(JwsGeneral.serializer(), general)
            val parsed = JWSObjectJSON.parse(serialized)

            parsed.signatures.size shouldBe 2
            parsed.signatures[0].verify(it.verifier1).shouldBeTrue()
            parsed.signatures[1].verify(it.verifier2).shouldBeTrue()
            parsed.signatures[0].header.keyID shouldBe null
            parsed.signatures[1].header.keyID shouldBe null
            parsed.signatures[0].unprotectedHeader.keyID shouldBe "kid-1"
            parsed.signatures[1].unprotectedHeader.keyID shouldBe "kid-2"
            general.getHeaderAt(0) shouldBe flattened1.jwsHeader
            general.getHeaderAt(1) shouldBe flattened2.jwsHeader
        }
    }
}