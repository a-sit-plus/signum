package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.testballoon.matrix.*
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.json.JsonElement
import java.security.interfaces.RSAPublicKey

val JwsCompactVectorTest by matrixSuite {

    compact("JWS can be parsed and verified") - {
        val testvec = javaClass.classLoader.getResourceAsStream("JwsTestVectors.txt")?.reader()?.readLines()
            ?: throw Exception("TestVectors not found")

        data(testvec) test { input ->
            val parsed = JwsCompact<SigningHeader, JsonElement>(input)

            val publicKey = CryptoPublicKey.fromDid(parsed.header.keyId.shouldNotBeNull())

            val jvmVerifier =
                if (publicKey is CryptoPublicKey.EC) ECDSAVerifier(publicKey.toJcaPublicKey())
                else RSASSAVerifier(publicKey.toJcaPublicKey() as RSAPublicKey)

            val result = JWSObject.parse(parsed.jws.toString()).verify(jvmVerifier)
            result.shouldBeTrue()
        }
    }

}
