import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.jws.JwsSigned
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.Signature

class JwsSignedTest : FreeSpec({

    "JWS can be parsed and verified" - {
        val testvec = javaClass.classLoader.getResourceAsStream("JwsTestVectors.txt")?.reader()?.readLines()
            ?: throw Exception("TestVectors not found")

        for (input in testvec) {
            val parsed = JwsSigned.parse(input)
            parsed.shouldNotBeNull()

            val publicKey = parsed.header.publicKey
            publicKey.shouldNotBeNull()
            publicKey.shouldBeInstanceOf<CryptoPublicKey.Ec>()
            val jcaKey = publicKey.getJcaPublicKey().getOrThrow()
            val asn1Signature = parsed.signature.encodeToDer()
            val signatureInput = parsed.plainSignatureInput.encodeToByteArray()

            val result = Signature.getInstance("SHA256withECDSA").apply {
                initVerify(jcaKey)
                update(signatureInput)
            }.verify(asn1Signature)
            result.shouldBeTrue()
        }
    }
})
