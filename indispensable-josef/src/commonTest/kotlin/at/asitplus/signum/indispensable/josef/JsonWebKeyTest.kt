package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.TestDiscoverable
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

@OptIn(ExperimentalStdlibApi::class)
val JsonWebKeyTest by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {

    class Context {
        val curve: ECCurve = ECCurve.SECP_256_R_1
        val x: ByteArray = Random.nextBytes(32)
        val y: ByteArray = Random.nextBytes(32)
        val ecKey: JsonWebKey = JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y)
        val n: ByteArray = Random.nextBytes(1024)
        val e: ByteArray = Random.nextBytes(16)
        val rsaKey: JsonWebKey = JsonWebKey(type = JwkType.RSA, n = n, e = e)
    }

    // This is a suite-scoped context: All tests within this suite get the same context.
    val context = testFixture { Context() }

    @TestDiscoverable
    fun testWithContext(name: String, action: suspend Context.() -> Unit) = test(name) {
        context().action()
        // For a test-scoped context (each test gets a fresh one), remove the fixture and replace the above line with
        //     Context().action()
        // But why supply each test with a different setup? In this case, context A might succeed on test 1, but
        // fail on test 2. But test 2 never sees context A, as it gets a fresh one. Better test each context with
        // the entire set of tests that apply.
    }

    testWithContext("Thumbprint for minimal EC Key") {
        val newKey = JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y)

        newKey.jwkThumbprint shouldBe ecKey.jwkThumbprint
    }

    testWithContext("Thumbprint for EC Key with additional properties") {
        val newKey = JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y, publicKeyUse = "foo")

        newKey.jwkThumbprint shouldBe ecKey.jwkThumbprint
    }

    testWithContext("Thumbprint for EC Key with keyId") {
        val newKey = JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y, keyId = "foo")

        newKey.jwkThumbprint shouldBe ecKey.jwkThumbprint
    }

    testWithContext("Thumbprint for minimal RSA Key") {
        val newKey = JsonWebKey(type = JwkType.RSA, n = n, e = e)

        newKey.jwkThumbprint shouldBe rsaKey.jwkThumbprint
    }

    testWithContext("Thumbprint for RSA Key with additional properties") {
        val newKey = JsonWebKey(type = JwkType.RSA, n = n, e = e, algorithm = JwsAlgorithm.Signature.RS256)

        newKey.jwkThumbprint shouldBe rsaKey.jwkThumbprint
    }

    testWithContext("Thumbprint for RSA Key with keyId") {
        val newKey = JsonWebKey(type = JwkType.RSA, n = n, e = e, keyId = "foo")

        newKey.jwkThumbprint shouldBe rsaKey.jwkThumbprint
    }

    testWithContext("Thumbprint for fixed Key from RFC 7638") {
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

    testWithContext("RSA Key should properly encode n and e (RFC 7518 sample)") {
        val key = CryptoPublicKey.RSA(
            n = Asn1Integer.fromUnsignedByteArray(("80".repeat(256)).hexToByteArray()), // high bit is set
            e = Asn1Integer(65537u) // explicit example from RFC7518 6.3.1.2
        ).toJsonWebKey()
        key.n!!.size shouldBe 256
        key.e!! shouldBe byteArrayOf(0x01, 0x00, 0x01)
    }

}
