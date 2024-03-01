import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import at.asitplus.crypto.datatypes.asn1.ensureSize
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldHaveMinLength
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class JsonWebKeyJvmTest : FreeSpec({

    lateinit var ecCurve: EcCurve
    lateinit var keyPair: KeyPair
    lateinit var keyPairRSA: KeyPair

    beforeTest {
        ecCurve = EcCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
        keyPairRSA = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.genKeyPair()
    }

    "JWK can be created from Coordinates" - {
        val xFromBc = (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val yFromBc = (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val pubKey = CryptoPublicKey.Ec(ecCurve, xFromBc, yFromBc)
        val jsonWebKey = pubKey.toJsonWebKey()

        jsonWebKey.shouldNotBeNull()
        jsonWebKey.x shouldBe xFromBc
        jsonWebKey.y shouldBe yFromBc
        jsonWebKey.keyId.shouldNotBeNull()
        jsonWebKey.keyId shouldHaveMinLength 32

        "it can be recreated from keyId" {
            val recreatedJwk = JsonWebKey.fromDid(jsonWebKey.keyId!!).getOrThrow()
            recreatedJwk.shouldNotBeNull()
            recreatedJwk.keyId shouldBe jsonWebKey.keyId
            recreatedJwk.x shouldBe jsonWebKey.x
            recreatedJwk.y shouldBe jsonWebKey.y
        }

        "it can be converted back to CryptoPublicKey" {
            val recreatedPubKey = jsonWebKey.toCryptoPublicKey().getOrThrow()
            (pubKey == recreatedPubKey) shouldBe true
        }
    }

    "JWK can be created from n and e" - {
        val nFromBc = (keyPairRSA.public as RSAPublicKey).modulus.toByteArray()
        val eFromBc = (keyPairRSA.public as RSAPublicKey).publicExponent.toInt()
        val pubKey = CryptoPublicKey.Rsa(nFromBc, eFromBc)
        val jwk = pubKey.toJsonWebKey()

        jwk.shouldNotBeNull()
        jwk.n shouldBe nFromBc
        jwk.e shouldBe eFromBc.encodeToByteArray()
        jwk.keyId.shouldNotBeNull()

        "it can be converted back to CryptoPublicKey" {
            val recreatedPubKey = jwk.toCryptoPublicKey().getOrThrow()
            (pubKey == recreatedPubKey) shouldBe true
        }

        "it can be recreated from keyId" {
            val recreatedJwk = JsonWebKey.fromDid(jwk.keyId!!).getOrThrow()
            recreatedJwk.shouldNotBeNull()
            recreatedJwk.keyId shouldBe jwk.keyId
            recreatedJwk.n shouldBe jwk.n
            recreatedJwk.e shouldBe jwk.e
        }

    }

})
