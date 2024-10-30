package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.getJcaPublicKey
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.json.JsonElement
import java.security.interfaces.RSAPublicKey

class JwsSignedTest : FreeSpec({

    "JWS can be parsed and verified" - {
        val testvec = javaClass.classLoader.getResourceAsStream("JwsTestVectors.txt")?.reader()?.readLines()
            ?: throw Exception("TestVectors not found")

        withData(testvec) { input ->
            val parsed = JwsSigned.deserialize<JsonElement>(input).getOrThrow()

            val publicKey = parsed.header.publicKey.shouldNotBeNull()

            val jvmVerifier =
                if (publicKey is CryptoPublicKey.EC) ECDSAVerifier(publicKey.getJcaPublicKey().getOrThrow())
                else RSASSAVerifier(publicKey.getJcaPublicKey().getOrThrow() as RSAPublicKey)

            val result = JWSObject.parse(parsed.serialize()).verify(jvmVerifier)
            result.shouldBeTrue()
        }
    }
})
