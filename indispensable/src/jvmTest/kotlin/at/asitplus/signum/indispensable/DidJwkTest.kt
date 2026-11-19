package at.asitplus.signum.indispensable

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import java.security.KeyPairGenerator

private fun didJwkOf(json: String) = "did:jwk:" + json.encodeToByteArray().encodeToString(Base64UrlStrict)
private fun String.didJwkPayload() = removePrefix("did:jwk:").decodeToByteArray(Base64UrlStrict).decodeToString()

/** P-256 example from the did:jwk specification */
private const val SPEC_P256_JSON =
    """{"crv":"P-256","kty":"EC","x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}"""
private const val SPEC_P256_DID =
    "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"

/** X25519 example from the did:jwk specification (OKP keys are not supported by Signum) */
private const val SPEC_X25519_DID =
    "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"

val DidJwkTest by matrixSuite {

    "Specification P-256 vector" - {
        "decodes" {
            val key = CryptoPublicKey.fromDid(SPEC_P256_DID)
            key.shouldBeInstanceOf<EcdsaPublicKey>().curve shouldBe ECCurve.SECP_256_R_1
            key.didJwkEncoded shouldBe SPEC_P256_DID
            SPEC_P256_DID.didJwkPayload() shouldBe SPEC_P256_JSON
        }
        "decodes with DID URL fragment" {
            CryptoPublicKey.fromDid("$SPEC_P256_DID#0") shouldBe CryptoPublicKey.fromDid(SPEC_P256_DID)
        }
        "member order of the input does not matter" {
            val reordered = didJwkOf(
                """{"kty":"EC","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE","x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","crv":"P-256","use":"sig"}"""
            )
            CryptoPublicKey.fromDid(reordered).didJwkEncoded shouldBe SPEC_P256_DID
        }
        "is interchangeable with did:key" {
            val key = CryptoPublicKey.fromDid(SPEC_P256_DID)
            CryptoPublicKey.fromDid(key.didEncoded) shouldBe key
        }
    }

    "EC round trip" - {
        listOf(256, 384, 521).asData() - { bits ->
            val keys = List(5) {
                KeyPairGenerator.getInstance("EC").apply { initialize(bits) }.genKeyPair().public.toCryptoPublicKey()
            }
            data(keys, nameFn = { it.didJwkEncoded }) test { key ->
                key.didJwkEncoded shouldStartWith "did:jwk:"
                CryptoPublicKey.fromDid(key.didJwkEncoded) shouldBe key
                CryptoPublicKey.fromDid(key.didJwkEncoded + "#0") shouldBe key
                key as EcdsaPublicKey
                key.didJwkEncoded.didJwkPayload() shouldBe
                        """{"crv":"${key.curve.jwkName}","kty":"EC",""" +
                        """"x":"${key.xBytes.encodeToString(Base64UrlStrict)}",""" +
                        """"y":"${key.yBytes.encodeToString(Base64UrlStrict)}"}"""
            }
        }
    }

    "RSA round trip" - {
        listOf(1024, 2048, 4096).asData() - { bits ->
            val key = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.genKeyPair().public
                .toCryptoPublicKey()
            "$bits bits" {
                CryptoPublicKey.fromDid(key.didJwkEncoded) shouldBe key
                key as RsaPublicKey
                key.didJwkEncoded.didJwkPayload() shouldBe
                        """{"e":"${key.e.magnitude.encodeToString(Base64UrlStrict)}","kty":"RSA",""" +
                        """"n":"${key.n.magnitude.encodeToString(Base64UrlStrict)}"}"""
            }
        }
    }

    "Rejects invalid input" - {
        "private EC key" {
            val withD = didJwkOf(SPEC_P256_JSON.dropLast(1) + ""","d":"AAAA"}""")
            shouldThrow<IllegalArgumentException> { CryptoPublicKey.fromDid(withD) }
        }
        "private RSA key" {
            val key = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.genKeyPair().public
                .toCryptoPublicKey()
            val withPrimes = didJwkOf(key.didJwkEncoded.didJwkPayload().dropLast(1) + ""","p":"AAAA","q":"AAAA"}""")
            shouldThrow<IllegalArgumentException> { CryptoPublicKey.fromDid(withPrimes) }
        }
        "symmetric key" {
            shouldThrow<IllegalArgumentException> {
                CryptoPublicKey.fromDid(didJwkOf("""{"k":"AAAAAAAAAAAAAAAAAAAAAA","kty":"oct"}"""))
            }
        }
        "unsupported key type (spec X25519 vector)" {
            shouldThrow<UnsupportedCryptoException> { CryptoPublicKey.fromDid(SPEC_X25519_DID) }
        }
        "unsupported curve" {
            shouldThrow<UnsupportedCryptoException> {
                CryptoPublicKey.fromDid(didJwkOf(SPEC_P256_JSON.replace("P-256", "P-192")))
            }
        }
        "missing coordinate" {
            shouldThrow<UnsupportedCryptoException> {
                CryptoPublicKey.fromDid(didJwkOf("""{"crv":"P-256","kty":"EC","x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0"}"""))
            }
        }
        "point not on curve" {
            shouldThrowAny {
                CryptoPublicKey.fromDid(didJwkOf(SPEC_P256_JSON.replace("\"x\":\"a", "\"x\":\"b")))
            }
        }
        "not base64url" {
            shouldThrowAny { CryptoPublicKey.fromDid("did:jwk:not!base64") }
        }
        "not JSON" {
            shouldThrowAny { CryptoPublicKey.fromDid(didJwkOf("not json")) }
        }
        "unknown DID method" {
            shouldThrow<IllegalArgumentException> { CryptoPublicKey.fromDid("did:web:example.com") }
        }
    }
}
