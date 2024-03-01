import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.jws.JwsSigned
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import java.security.interfaces.RSAPublicKey

class JwsSignedTest : FreeSpec({

    "JWS can be parsed and verified" - {
        val testvec = javaClass.classLoader.getResourceAsStream("JwsTestVectors.txt")?.reader()?.readLines()
            ?: throw Exception("TestVectors not found")

        withData(testvec) { input ->
            val parsed = JwsSigned.parse(input)
            parsed.shouldNotBeNull()

            val publicKey = parsed.header.publicKey
            publicKey.shouldNotBeNull()

            val jvmVerifier =
                if (publicKey is CryptoPublicKey.Ec) ECDSAVerifier(publicKey.getJcaPublicKey().getOrThrow())
                else RSASSAVerifier(publicKey.getJcaPublicKey().getOrThrow() as RSAPublicKey)

            val result = JWSObject.parse(parsed.serialize()).verify(jvmVerifier)
            result.shouldBeTrue()
        }
    }
})
