package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.dsl.ec
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.crypto.ECDSAVerifier
import io.kotest.engine.runBlocking
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import java.security.interfaces.ECPublicKey

val JwsJvmTest by matrixSuite {
    class Context {
        val payload = SigningPayload("alice")
        val signers = List(2) { index ->
            runBlocking {
                Signer.Ephemeral {
                    ec {
                        curve = if (index == 0) ECCurve.SECP_256_R_1 else ECCurve.SECP_384_R_1
                        digest = if (index == 0) Digest.SHA256 else Digest.SHA384
                    }
                }
            }
        }
        val jwsSigner = JwsSigner(signers)
        val verifiers = signers.map { ECDSAVerifier(it.publicKey.toJcaPublicKey() as ECPublicKey) }
        val headers = signers.mapIndexed { index, signer ->
            SigningHeader(
                algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                keyId = "kid-${index + 1}",
                type = "application/example+jws",
            )
        }
    }

    fixture(::Context) - {
        "compact typed JWS can be encoded and verified by Nimbus" { context ->
            val typed = context.jwsSigner.signCompact(context.headers[0], context.payload)
            val parsed = JWSObject.parse(typed.raw.toString())

            parsed.verify(context.verifiers[0]).shouldBeTrue()
            parsed.header.keyID shouldBe "kid-1"
            parsed.payload.toString() shouldBe """{"sub":"alice"}"""
        }

        "flattened typed JWS can be serialized and verified by Nimbus" { context ->
            val placement = setOf(JwsHeader.SerialNames.KEY_ID)
            val typed = context.jwsSigner.signFlattened(context.headers[0], context.payload, placement)
            val parsed = JWSObjectJSON.parse(joseCompliantSerializer.encodeToString(typed.raw))

            parsed.signatures.single().verify(context.verifiers[0]).shouldBeTrue()
            parsed.signatures.single().header.keyID shouldBe null
            parsed.signatures.single().unprotectedHeader.keyID shouldBe "kid-1"
        }

        "general typed JWS can be serialized and verified by Nimbus" { context ->
            val placement = setOf(JwsHeader.SerialNames.KEY_ID)
            val typed = context.jwsSigner.signGeneral(context.payload, context.headers.map { header ->
                JwsHeaderWrapped(header, placement)
            })
            val parsed = JWSObjectJSON.parse(joseCompliantSerializer.encodeToString(typed.raw))

            parsed.signatures.size shouldBe 2
            parsed.signatures.forEachIndexed { index, signature ->
                signature.verify(context.verifiers[index]).shouldBeTrue()
                signature.header.keyID shouldBe null
                signature.unprotectedHeader.keyID shouldBe "kid-${index + 1}"
            }
        }
    }
}
