package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toCryptoPublicKey
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.az
import io.kotest.property.arbitrary.string
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import kotlin.random.Random
import kotlin.time.Clock
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val JwkTest  by testSuite {
    "EC" - {
        withDataSuites(256, 384, 521) { bits ->
            val keys = List<ECPublicKey>(10) {
                val ecKp = KeyPairGenerator.getInstance("EC").apply {
                    initialize(bits)
                }.genKeyPair()
                ecKp.public as ECPublicKey
            }
            withData(
                nameFn = {
                    "(x: ${
                        it.w.affineX.toByteArray().encodeToString(Base64Strict)
                    } y: ${it.w.affineY.toByteArray().encodeToString(Base64Strict)})"
                },
                keys
            ) { pubKey ->

                val cryptoPubKey = pubKey.toCryptoPublicKey().getOrThrow().also { it.jwkId = it.didEncoded }
                val own = cryptoPubKey.toJsonWebKey()
                own.keyId shouldBe cryptoPubKey.jwkId
                own.shouldNotBeNull()

                own.toCryptoPublicKey().getOrThrow().iosEncoded shouldBe cryptoPubKey.iosEncoded
                CryptoPublicKey.fromDid(own.keyId!!) shouldBe cryptoPubKey
            }
        }
    }

    "Serialize and deserialize EC" {
        val jwk = JsonWebKey(
            curve = ECCurve.SECP_256_R_1,
            type = JwkType.EC,
            x = Random.nextBytes(32),
            y = Random.nextBytes(32),
            publicKeyUse = Random.nextBytes(16).encodeToString(Base64Strict),
            keyOperations = setOf(Random.nextBytes(16).encodeToString(Base64Strict)),
            certificateUrl = Random.nextBytes(16).encodeToString(Base64Strict),
            certificateChain = listOf(randomCertificate()),
            certificateSha1Thumbprint = Random.nextBytes(20),
            certificateSha256Thumbprint = Random.nextBytes(32),
        )

        val serialized = joseCompliantSerializer.encodeToString(jwk)
        val parsed = joseCompliantSerializer.decodeFromString<JsonWebKey>(serialized)

        parsed shouldBe jwk
    }

    "Deserialize BP keys" {
        val input = """
            {
              "alg": "ECDH-ES",
              "crv": "BP-256",
              "kid": "9d1db5b5-0a76-11f0-858d-026b3e565740",
              "kty": "EC",
              "use": "enc",
              "x": "fk-0X35Cj8-8TDmfEn8grS5f2x7AzmAnkxc17i8Lae8",
              "y": "XIj2dcra7tC9cQ6HRlM1kae5fGVQyoIj_bOFlpA4w5k"
            }
        """.trimIndent()

        val parsed = joseCompliantSerializer.decodeFromString<JsonWebKey>(input)

        parsed.algorithm shouldBe JweAlgorithm.ECDH_ES
        parsed.curve.shouldBeNull()
        parsed.keyId shouldBe "9d1db5b5-0a76-11f0-858d-026b3e565740"
        parsed.type shouldBe JwkType.EC
        parsed.publicKeyUse shouldBe "enc"
    }

    "Serialize and deserialize Algos" - {
        withData(JsonWebAlgorithm.entries) { jwa ->
            val jwk = JsonWebKey(
                curve = ECCurve.SECP_256_R_1,
                type = JwkType.EC,
                algorithm = jwa,
                x = Random.nextBytes(32),
                y = Random.nextBytes(32),
                publicKeyUse = Random.nextBytes(16).encodeToString(Base64Strict),
                keyOperations = setOf(Random.nextBytes(16).encodeToString(Base64Strict)),
                certificateUrl = Random.nextBytes(16).encodeToString(Base64Strict),
                certificateChain = listOf(randomCertificate()),
                certificateSha1Thumbprint = Random.nextBytes(20),
                certificateSha256Thumbprint = Random.nextBytes(32),
            )

            val serialized = joseCompliantSerializer.encodeToString(jwk)
            val parsed = joseCompliantSerializer.decodeFromString<JsonWebKey>(serialized)

            parsed shouldBe jwk
        }
    }

    "Serialize and deserialize RSA" {
        val jwk = JsonWebKey(
            type = JwkType.RSA,
            n = Random.nextBytes(64),
            e = Random.nextBytes(8),
            publicKeyUse = Random.nextBytes(16).encodeToString(Base64Strict),
            keyOperations = setOf(Random.nextBytes(16).encodeToString(Base64Strict)),
            certificateUrl = Random.nextBytes(16).encodeToString(Base64Strict),
            certificateChain = listOf(randomCertificate()),
            certificateSha1Thumbprint = Random.nextBytes(20),
            certificateSha256Thumbprint = Random.nextBytes(32),
        )

        val parsed = joseCompliantSerializer.decodeFromString<JsonWebKey>(joseCompliantSerializer.encodeToString(jwk))

        parsed shouldBe jwk
    }

    "Regression test: JWK (no keyId) -> CryptoPublicKey -> JWK (no keyId)" {
        val key = randomCertificate().decodedPublicKey.getOrThrow().toJsonWebKey()
        key.keyId shouldBe null
        val cpk = key.toCryptoPublicKey().getOrThrow()
        cpk.toJsonWebKey().keyId shouldBe null
        val kid = Arb.string(minSize = 16, maxSize = 16, Codepoint.az()).sample(
            RandomSource.default()
        ).value
        cpk.toJsonWebKey(keyId = kid).keyId shouldBe kid
    }
}

private fun randomCertificate() = X509Certificate(
    TbsCertificate(
        serialNumber = Random.nextBytes(16),
        issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        publicKey = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
            .genKeyPair().public.toCryptoPublicKey().getOrThrow(),
        signatureAlgorithm = X509SignatureAlgorithm.ES256,
        subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        validFrom = Asn1Time(Clock.System.now()),
        validUntil = Asn1Time(Clock.System.now()),
    ),
    X509SignatureAlgorithm.ES256,
    CryptoSignature.EC.fromRS(
        BigInteger.fromByteArray(Random.nextBytes(16), Sign.POSITIVE),
        BigInteger.fromByteArray(Random.nextBytes(16), Sign.POSITIVE)
    )
)