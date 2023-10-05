import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
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

class JsonWebKeyJvmTest : FreeSpec({

    lateinit var ecCurve: EcCurve
    lateinit var keyPair: KeyPair

    beforeTest {
        ecCurve = EcCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
    }

    "JWK can be created from Coordinates" - {
        val xFromBc = (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val yFromBc = (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val jsonWebKey = CryptoPublicKey.Ec.fromCoordinates(ecCurve, xFromBc, yFromBc).toJsonWebKey()

        jsonWebKey.shouldNotBeNull()
        jsonWebKey.x shouldBe xFromBc
        jsonWebKey.y shouldBe yFromBc
        jsonWebKey.keyId.shouldNotBeNull()
        jsonWebKey.keyId shouldHaveMinLength 32

        "it can be recreated" {
            val recreatedJwk = JsonWebKey.fromKeyId(jsonWebKey.keyId!!)
            recreatedJwk.shouldNotBeNull()
            recreatedJwk.keyId shouldBe jsonWebKey.keyId
            recreatedJwk.x shouldBe jsonWebKey.x
            recreatedJwk.y shouldBe jsonWebKey.y
        }
    }

    "JWK can be created from ANSI X962" - {
        val xFromBc = (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val yFromBc = (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val ansiX962 = byteArrayOf(0x04) + xFromBc + yFromBc
        val jsonWebKey = CryptoPublicKey.Ec.fromAnsiX963Bytes(ansiX962)!!.toJsonWebKey()

        jsonWebKey.shouldNotBeNull()
        jsonWebKey.x shouldBe xFromBc
        jsonWebKey.y shouldBe yFromBc
        jsonWebKey.keyId.shouldNotBeNull()
        jsonWebKey.keyId shouldHaveMinLength 32
        jsonWebKey.toAnsiX963ByteArray().getOrThrow() shouldBe ansiX962

        "it can be recreated" {
            val recreatedJwk = JsonWebKey.fromKeyId(jsonWebKey.keyId!!)
            recreatedJwk.shouldNotBeNull()
            recreatedJwk.keyId shouldBe jsonWebKey.keyId
            recreatedJwk.x shouldBe jsonWebKey.x
            recreatedJwk.y shouldBe jsonWebKey.y
            jsonWebKey.toAnsiX963ByteArray().getOrThrow() shouldBe ansiX962
        }
    }

})
