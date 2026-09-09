package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.signature
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.crypto.ECDSAVerifier
import at.asitplus.testballoon.matrix.*
import io.kotest.engine.runBlocking
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import java.security.interfaces.ECPublicKey

val JwsJvmTest by matrixSuite {

    class Context {
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()

        val signer1 = runBlocking {   Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()}

        val signer2 = runBlocking {  Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow()}

        val verifier1 = ECDSAVerifier(signer1.publicKey.toJcaPublicKey() as ECPublicKey)
        val verifier2 = ECDSAVerifier(signer2.publicKey.toJcaPublicKey() as ECPublicKey)

        fun signerFor(signer: Signer): suspend (ByteArray) -> ByteArray = { input ->
            signer.sign(input).signature.rawByteArray
        }
    }

    fixture(::Context) - {

        "compact JWS can be encoded and verified by Nimbus" { it ->
            val header = JwsHeader(
                algorithm = it.signer1.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                keyId = "kid-1",
                type = "application/example+jws",
            )
            val compact = JwsCompact.invoke(
                protectedHeader = header,
                payload = it.payload,
                signer = it.signerFor(it.signer1),
            )

            val serialized = compact.toString()
            val parsed = JWSObject.parse(serialized)

            parsed.verify(it.verifier1).shouldBeTrue()
            parsed.header.keyID shouldBe "kid-1"
            compact.wrappedHeader.header shouldBe header
            compact.wrappedHeader.unprotectedMembers shouldBe emptySet()
        }

        "flattened JWS can be serialized and verified by Nimbus" { it ->
            val header = JwsHeader(
                algorithm = it.signer1.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                type = "application/example+jws",
                keyId = "kid-1",
            )
            val unprotectedMembers = setOf(JwsHeader.SerialNames.KEY_ID)
            val flattened = JwsFlattened.invoke(
                header = header,
                payload = it.payload,
                unprotectedMembers = unprotectedMembers,
                signer = it.signerFor(it.signer1),
            )

            val serialized = joseCompliantSerializer.encodeToString(JwsFlattened.serializer(), flattened)
            val parsed = JWSObjectJSON.parse(serialized)

            parsed.signatures.size shouldBe 1
            parsed.signatures.single().verify(it.verifier1).shouldBeTrue()
            parsed.signatures.single().header.keyID shouldBe null
            parsed.signatures.single().unprotectedHeader.keyID shouldBe "kid-1"
            flattened.wrappedHeader.header shouldBe header
            flattened.wrappedHeader.unprotectedMembers shouldBe unprotectedMembers
        }

        "general JWS can be serialized and verified by Nimbus" { it ->
            val flattened1 = JwsFlattened.invoke(
                header = JwsHeader(
                    algorithm = it.signer1.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                    keyId = "kid-1",
                ),
                payload = it.payload,
                unprotectedMembers = setOf(JwsHeader.SerialNames.KEY_ID),
                signer = it.signerFor(it.signer1),
            )
            val flattened2 = JwsFlattened.invoke(
                header = JwsHeader(
                    algorithm = it.signer2.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                    keyId = "kid-2",
                ),
                payload = it.payload,
                unprotectedMembers = setOf(JwsHeader.SerialNames.KEY_ID),
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
            general.wrappedHeaders[0] shouldBe flattened1.wrappedHeader
            general.wrappedHeaders[1] shouldBe flattened2.wrappedHeader
        }
    }
}
