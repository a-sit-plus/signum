package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import java.security.KeyPairGenerator

private fun didJwkOf(json: String) = "did:jwk:" + json.encodeToByteArray().encodeToString(Base64UrlStrict)

private const val SPEC_P256_DID =
    "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"

val JsonWebKeyDidJwkTest by matrixSuite {

    "fromDid retains additional JWK members" {
        val did = didJwkOf(
            """{"alg":"ES256","crv":"P-256","kid":"my-key","kty":"EC","use":"sig",""" +
                    """"x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}"""
        )
        val jwk = JsonWebKey.fromDid(did).getOrThrow()
        jwk.keyId shouldBe "my-key"
        jwk.publicKeyUse shouldBe "sig"
        jwk.algorithm shouldBe JwsAlgorithm.Signature.ES256
        jwk.toCryptoPublicKey().getOrThrow() shouldBe CryptoPublicKey.fromDid(SPEC_P256_DID)
        jwk.didJwkEncoded shouldBe SPEC_P256_DID
    }

    "fromDid uses the DID as keyId if the JWK has none" {
        val jwk = JsonWebKey.fromDid("$SPEC_P256_DID#0").getOrThrow()
        jwk.keyId shouldBe "$SPEC_P256_DID#0"
    }

    "fromDid rejects private keys" {
        val did = didJwkOf(
            """{"crv":"P-256","d":"AAAA","kty":"EC",""" +
                    """"x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}"""
        )
        JsonWebKey.fromDid(did).isFailure shouldBe true
    }

    "did:key and did:jwk resolve to the same key" {
        listOf("EC" to 256, "EC" to 384, "EC" to 521, "RSA" to 2048).forEach { (alg, bits) ->
            val key = KeyPairGenerator.getInstance(alg).apply { initialize(bits) }.genKeyPair().public
                .toCryptoPublicKey()
            val jwk = key.toJsonWebKey()
            jwk.didJwkEncoded shouldBe key.didJwkEncoded
            JsonWebKey.fromDid(key.didJwkEncoded).getOrThrow().toCryptoPublicKey().getOrThrow() shouldBe key
            JsonWebKey.fromDid(key.didEncoded).getOrThrow().toCryptoPublicKey().getOrThrow() shouldBe key
        }
    }
}
