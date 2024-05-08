package at.asitplus.crypto.datatypes.jws

import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.Asn1String
import at.asitplus.crypto.datatypes.asn1.Asn1Time
import at.asitplus.crypto.datatypes.fromJcaPublicKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.pki.AttributeTypeAndValue
import at.asitplus.crypto.datatypes.pki.RelativeDistinguishedName
import at.asitplus.crypto.datatypes.pki.TbsCertificate
import at.asitplus.crypto.datatypes.pki.X509Certificate
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
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

                val cryptoPubKey = CryptoPublicKey.Ec.fromJcaPublicKey(pubKey).getOrThrow()
                val own = cryptoPubKey.toJsonWebKey()
                own.keyId shouldBe cryptoPubKey.jwkId
                own.shouldNotBeNull()
                println(own.serialize())
                own.toCryptoPublicKey().getOrThrow().iosEncoded shouldBe cryptoPubKey.iosEncoded
                CryptoPublicKey.fromDid(own.keyId!!) shouldBe cryptoPubKey
            }
        }
    }

    "Serialize and deserialize EC" {
        val jwk = JsonWebKey(
            curve = EcCurve.SECP_256_R_1,
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

        val parsed = JsonWebKey.deserialize(jwk.serialize()).getOrThrow()

        parsed shouldBe jwk
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
})

private fun randomCertificate() = X509Certificate(
    TbsCertificate(
        serialNumber = Random.nextBytes(16),
        issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        publicKey = CryptoPublicKey.Ec.fromJcaPublicKey(KeyPairGenerator.getInstance("EC").apply { initialize(256) }
            .genKeyPair().public as ECPublicKey).getOrThrow(),
        signatureAlgorithm = CryptoAlgorithm.ES256,
        subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        validFrom = Asn1Time(Clock.System.now()),
        validUntil = Asn1Time(Clock.System.now()),
    ),
    CryptoAlgorithm.ES256,
    CryptoSignature.EC(Random.nextBytes(16), Random.nextBytes(16))
)