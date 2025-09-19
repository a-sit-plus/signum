package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.signature
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.json.JsonElement
import java.security.interfaces.RSAPublicKey

val JwsSignedTest  by testSuite{

    "JWS can be parsed and verified" - {
        val testvec = javaClass.classLoader.getResourceAsStream("JwsTestVectors.txt")?.reader()?.readLines()
            ?: throw Exception("TestVectors not found")

        withData(testvec) { input ->
            val parsed = JwsSigned.deserialize<JsonElement>(JsonElement.serializer(), input).getOrThrow()

            val publicKey = parsed.header.publicKey.shouldNotBeNull()

            val jvmVerifier =
                if (publicKey is CryptoPublicKey.EC) ECDSAVerifier(publicKey.toJcaPublicKey().getOrThrow())
                else RSASSAVerifier(publicKey.toJcaPublicKey().getOrThrow() as RSAPublicKey)

            val result = JWSObject.parse(parsed.serialize()).verify(jvmVerifier)
            result.shouldBeTrue()
        }
    }

    "JWS example" {
        val signer = Signer.Ephemeral {
            ec { curve = ECCurve.SECP_256_R_1 }
        }.getOrThrow() //TODO handle error

        val header = JwsHeader(
            algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            jsonWebKey = signer.publicKey.toJsonWebKey()
        )
        val payload = byteArrayOf(1, 3, 3, 7)

        val plainSignatureInput = JwsSigned.prepareJwsSignatureInput(header, payload)

        val signature = signer.sign(plainSignatureInput).signature //TODO: handle error
        println(JwsSigned(header, payload, signature, plainSignatureInput).serialize())// this we can verify on jwt.io
    }
}
