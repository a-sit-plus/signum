package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.fromUncompressed
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.indispensable.asn1.toAsn1Integer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldHaveMinLength
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

private fun ByteArray.trimLeadingZeros() =
    when (val i = this.indexOfFirst { it != 0x00.toByte() }) {
        -1 -> byteArrayOf(0x00)
        0 -> this
        else -> this.copyOfRange(i, this.size)
    }

val JsonWebKeyJvmTest by testSuite {

    lateinit var ecCurve: ECCurve
    lateinit var keyPair: KeyPair
    lateinit var keyPairRSA: KeyPair

    testConfig = TestConfig.aroundEach {
        ecCurve = ECCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
        keyPairRSA = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.genKeyPair()
        it()
    }

    "JWK can be created from Coordinates" - {
        val xFromBc = (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLength.bytes)
        val yFromBc = (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLength.bytes)
        val pubKey = fromUncompressed(ecCurve, xFromBc, yFromBc).also { it.jwkId = it.didEncoded }
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
        val nFromBc = (keyPairRSA.public as RSAPublicKey).modulus
        val eFromBc = (keyPairRSA.public as RSAPublicKey).publicExponent
        val pubKey = CryptoPublicKey.RSA(
            nFromBc.toAsn1Integer() as Asn1Integer.Positive,
            eFromBc.toAsn1Integer() as Asn1Integer.Positive)
                .also { it.jwkId = it.didEncoded }
        val jwk = pubKey.toJsonWebKey()

        jwk.shouldNotBeNull()
        jwk.n shouldBe nFromBc.toByteArray().trimLeadingZeros()
        jwk.e shouldBe eFromBc.toByteArray().trimLeadingZeros()
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
}
