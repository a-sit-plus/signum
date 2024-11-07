package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlin.random.Random

class JsonWebKeyTest : FreeSpec({

    lateinit var curve: ECCurve
    lateinit var x: ByteArray
    lateinit var y: ByteArray
    lateinit var ecKey: JsonWebKey
    lateinit var n: ByteArray
    lateinit var e: ByteArray
    lateinit var rsaKey: JsonWebKey

    beforeTest {
        curve = ECCurve.SECP_256_R_1
        x = Random.nextBytes(32)
        y = Random.nextBytes(32)
        ecKey = JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y)
        n = Random.nextBytes(1024)
        e = Random.nextBytes(16)
        rsaKey = JsonWebKey(type = JwkType.RSA, n = n, e = e)
    }

    "Thumbprint for minimal EC Key" - {
        val newKey = JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y)

        newKey.jwkThumbprint shouldBe ecKey.jwkThumbprint
    }

    "Thumbprint for EC Key with additional properties" - {
        val newKey = JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y, publicKeyUse = "foo")

        newKey.jwkThumbprint shouldBe ecKey.jwkThumbprint
    }

    "Thumbprint for EC Key with keyId" - {
        val newKey = JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y, keyId = "foo")

        newKey.jwkThumbprint shouldBe ecKey.jwkThumbprint
    }

    "Thumbprint for minimal RSA Key" - {
        val newKey = JsonWebKey(type = JwkType.RSA, n = n, e = e)

        newKey.jwkThumbprint shouldBe rsaKey.jwkThumbprint
    }

    "Thumbprint for RSA Key with additional properties" - {
        val newKey = JsonWebKey(type = JwkType.RSA, n = n, e = e, algorithm = JwsAlgorithm.RS256)

        newKey.jwkThumbprint shouldBe rsaKey.jwkThumbprint
    }

    "Thumbprint for RSA Key with keyId" - {
        val newKey = JsonWebKey(type = JwkType.RSA, n = n, e = e, keyId = "foo")

        newKey.jwkThumbprint shouldBe rsaKey.jwkThumbprint
    }

    "Thumbprint for fixed Key from RFC 7638" - {
        val parsedN = ("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
                "aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
                "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
                "GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
                "91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
                "BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw").decodeToByteArray(Base64UrlStrict)
        val parsedE = "AQAB".decodeToByteArray(Base64UrlStrict)
        val key = JsonWebKey(type = JwkType.RSA, n = parsedN, e = parsedE)

        key.jwkThumbprint shouldBe "urn:ietf:params:oauth:jwk-thumbprint:sha256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    }

})