package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.property.azstring
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import kotlin.random.Random

class JwkTest : FreeSpec({
    "EC" - {
        withData(256, 384, 521) { bits ->
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

                val cryptoPubKey =
                    CryptoPublicKey.EC.fromJcaPublicKey(pubKey).getOrThrow().also { it.jwkId = it.didEncoded }
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

        val serialized = jwk.serialize()
        val parsed = JsonWebKey.deserialize(serialized).getOrThrow()

        parsed shouldBe jwk
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

            val serialized = jwk.serialize()
            val parsed = JsonWebKey.deserialize(serialized).getOrThrow()

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

        val parsed = JsonWebKey.deserialize(jwk.serialize()).getOrThrow()

        parsed shouldBe jwk
    }

    "Regression test: JWK (no keyId) -> CryptoPublicKey -> JWK (no keyId)" {
        val key = randomCertificate().publicKey.toJsonWebKey()
        key.keyId shouldBe null
        val cpk = key.toCryptoPublicKey().getOrThrow()
        cpk.toJsonWebKey().keyId shouldBe null
        val kid = Random.azstring(16)
        cpk.toJsonWebKey(keyId = kid).keyId shouldBe kid
    }
})

private fun randomCertificate() = X509Certificate(
    TbsCertificate(
        serialNumber = Random.nextBytes(16),
        issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        publicKey = CryptoPublicKey.EC.fromJcaPublicKey(KeyPairGenerator.getInstance("EC").apply { initialize(256) }
            .genKeyPair().public as ECPublicKey).getOrThrow(),
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