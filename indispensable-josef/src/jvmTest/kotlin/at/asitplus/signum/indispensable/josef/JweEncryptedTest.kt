package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.symmetric.randomKey
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.AESEncrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import at.asitplus.test.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import java.net.URI
import javax.crypto.KeyGenerator
import kotlin.random.Random


class JweEncryptedTest : FreeSpec({

    "Minimal JWE can be parsed and verified" - {
        val input = Random.Default.nextBytes(32)

        val jweNimbus = JWEObject(
            JWEHeader.Builder(
                JWEAlgorithm.A128KW, EncryptionMethod.A128GCM
            ).build(),
            Payload(input)
        )

        val secretKey = KeyGenerator.getInstance("AES").apply { init(128) }.generateKey()
        jweNimbus.encrypt(AESEncrypter(secretKey))

        val parsed = JweEncrypted.deserialize(jweNimbus.serialize()).getOrThrow()

        parsed.header.algorithm shouldBe JweAlgorithm.A128KW
        parsed.header.encryption shouldBe JweEncryption.A128GCM
        parsed.ciphertext shouldBe jweNimbus.cipherText.decode()
    }

    "JWE with some attributes can be parsed and verified" - {
        val input = Random.Default.nextBytes(32)
        val apu = Random.nextBytes(32)
        val apv = Random.nextBytes(32)
        val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val jwk = ECKeyGenerator(Curve.P_256).generate().toPublicJWK()
        val kid = Random.nextBytes(16).encodeToString(Base16())
        val typ = Random.nextBytes(16).encodeToString(Base16())
        val cty = Random.nextBytes(16).encodeToString(Base16())
        val x5u = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)

        val jweNimbus = JWEObject(
            JWEHeader.Builder(
                JWEAlgorithm.ECDH_ES, EncryptionMethod.A256CBC_HS512
            ).agreementPartyUInfo(Base64URL.encode(apu))
                .agreementPartyVInfo(Base64URL.encode(apv))
                .jwkURL(URI.create(jku))
                .jwk(jwk)
                .keyID(kid)
                .type(JOSEObjectType(typ))
                .contentType(cty)
                .x509CertURL(URI.create(x5u))
                .build(),
            Payload(input)
        )

        jweNimbus.encrypt(ECDHEncrypter(ECKeyGenerator(Curve.P_256).generate()))

        val parsed = JweEncrypted.deserialize(jweNimbus.serialize()).getOrThrow()

        parsed.header.algorithm shouldBe JweAlgorithm.ECDH_ES
        parsed.header.encryption shouldBe JweEncryption.A256CBC_HS512
        parsed.header.agreementPartyUInfo shouldBe apu
        parsed.header.agreementPartyVInfo shouldBe apv
        parsed.header.jsonWebKeyUrl shouldBe jku
        val ourJwk = jwk.toECPublicKey().toCryptoPublicKey().getOrThrow().toJsonWebKey()
        parsed.header.jsonWebKey shouldBe ourJwk
        parsed.header.keyId shouldBe kid
        parsed.header.type shouldBe typ
        parsed.header.contentType shouldBe cty
        parsed.header.certificateUrl shouldBe x5u
        parsed.ciphertext shouldBe jweNimbus.cipherText.decode()
    }

    "JWE symmetric encryption" - {
        withData(JweAlgorithm.Symmetric.entries) { alg ->
            val plain = Random.nextBytes(32)
            val key = alg.randomKey().toJsonWebKey().getOrThrow()
            val ciphertext = key.encrypt(plain).getOrThrow()
            ciphertext.decrypt(key) shouldSucceedWith plain
        }
    }

})
