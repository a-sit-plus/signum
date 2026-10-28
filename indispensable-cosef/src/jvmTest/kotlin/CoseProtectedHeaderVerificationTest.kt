import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseMac
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.jcaSignatureBytes
import at.asitplus.signum.indispensable.parseJCASignature
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.builtins.ByteArraySerializer
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.spec.ECGenParameterSpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

/**
 * Status list CWT (tagged `COSE_Sign1`) from `https://dev.revocation.eudiw.dev`, signed with an
 * EUDI Wallet Reference Implementation test certificate contained in `x5chain` of the protected header.
 * Its protected header is encoded with the keys in order 1 (alg), 16 (typ), 33 (x5chain).
 */
private val eudiwStatusListCwt = (
        "0oRZA5WjASYQeBphcHBsaWNhdGlvbi9zdGF0dXNsaXN0K2N3dBghWQNwMIIDbDCCAxKgAwIBAgIUe4Kzlw4Ssz8pooCGrSEpkjac" +
                "V/EwCgYIKoZIzj0EAwIwVzEZMBcGA1UEAwwQUElEIElzc3VlciBDQSAwMjEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNl" +
                "IEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJMVTAeFw0yNjA5MjkxMjAxMjFaFw0yNzEyMjMxMjAxMjBaMHExGTAXBgNVBAMMEFBJ" +
                "RCBEUyAtIDAwMyBERVYxGDAWBgNVBGEMD0xFSUVVLTEyMzQ1Njc4OTEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIElt" +
                "cGxlbWVudGF0aW9uMQswCQYDVQQGEwJMVTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABORnbm/HI77Uib1+xkP6lJ68zsrLv0G8" +
                "DcTYAomX/wF48wOCIps9L6I2DuxE+8L5TQiloXIuOGP1A5wAqfbq33GjggGgMIIBnDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaA" +
                "FFxi+9GmJnpnPzVXFDj4B1jgh7PwMFkGCCsGAQUFBwEBBE0wSzBJBggrBgEFBQcwAoY9aHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRp" +
                "dy5kZXYvYWlhL1BJRElzc3VlckNBMDItTFUuY2FjZXJ0LnBlbTAqBgNVHREEIzAhhh9odHRwczovL2VjLmRldi5pc3N1ZXIuZXVk" +
                "aXcuZGV2MC4GA1UdIAQnMCUwIwYDKgMEMBwwGgYIKwYBBQUHAgEWDmV4YW1wbGUucG9saWN5MBsGA1UdJQQUMBIGByiBjF0FAQIG" +
                "ByiBtTQEAQIwQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3BpZF9DQV9MVV8wMi5j" +
                "cmwwHQYDVR0OBBYEFLoPAUp/N1j54IHVy0T9SpX+8Wk5MA4GA1UdDwEB/wQEAwIHgDAjBggrBgEFBQcBAwQXMBUwEwYGBACORgEG" +
                "MAkGBwQAi+xOAQEwCgYIKoZIzj0EAwIDSAAwRQIhAIg5MqvG9q06gf782ys0IKPbPQNawEkIzV+0Z8JmwIl/AiAGCdqzEgH2pFxx" +
                "sYJ+vEilJ3QV72xOsSKnPdfWrMsqAaBZAbClAnhwaHR0cHM6Ly9kZXYucmV2b2NhdGlvbi5ldWRpdy5kZXYvdG9rZW5fc3RhdHVz" +
                "X2xpc3QvRkMvb3JnLmlzby4xODAxMy41LjEubURMLzVmYTM4OWY0LTVkODAtNGI0Ni04YzI2LTU5YjY3ZTE5NTM3ZAQaauNGygYa" +
                "auH1Shn//hkOEBn//aJkYml0cwFjbHN0WQEZeNqNU0GOBCEIBGI2HDnu0Uz2AfMED3OYZ3Hch+3DRrFVdOyepRPFFigoEAhAgSFL" +
                "LEs+5rNq3tD+2kUAeFY92HorSzJ7AifyaB7NlNmCBu+9CpdYUca5oMNfPaRqsBHtGh2Ip5KAVsgAk1OHsBSlaug8RurYMzX/akSy" +
                "BZZlX3Aq3xPOXB8uPLk8OH/oKNDek/jO78yZbvHw3Txa6kfsUURnEw2RItxDaWG7xZGYte/I+duxNgldd+9sbgZC6izPpZXp415T" +
                "QwkTqz++SdzK/C26xoksWYg6GUwGuSqEPtQ6GfB24vHiLewZbvM8hqSwTiOcbGgOm2hhoKfLKXKpq6+MycVi/g8P7ZlZHPk6fWRR" +
                "ZcPHC3OYFRhYQH7yBmD6FZxd4AQulNQiOemIg3Ov7Onnj7I/ta3KBRNHGRI3zz12gM9mxeH5ZLh1BpLthMAIe2skglSeZo+TPCc="
        ).decodeToByteArray(Base64())

private fun CoseSigned<*>.verify(publicKey: PublicKey): Boolean =
    (protectedHeader.algorithm as CoseAlgorithm.Signature).algorithm.getJCASignatureInstance().run {
        initVerify(publicKey)
        update(prepareCoseSignatureInput())
        verify(signature.jcaSignatureBytes)
    }

private fun cbor(hex: String) = hex.decodeToByteArray(Base16())

/** CBOR byte string header for lengths < 256 */
private fun ByteArray.bstr(): ByteArray = when {
    size < 24 -> byteArrayOf((0x40 + size).toByte())
    else -> byteArrayOf(0x58, size.toByte())
} + this

val CoseProtectedHeaderVerificationTest by matrixSuite {

    // {16: "application/test", 1: -7 (ES256)}, i.e. not in the order Signum would encode it
    val protectedEs256 = cbor("A21070") + "application/test".encodeToByteArray() + cbor("0126")
    // {16: "application/test", 1: 5 (HS256)}
    val protectedHs256 = cbor("A21070") + "application/test".encodeToByteArray() + cbor("0105")

    "COSE_Sign1 with protected header in non-Signum key order verifies and round-trips" {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val payload = Random.nextBytes(32)
        val sigStructure = cbor("846A") + "Signature1".encodeToByteArray() +
                protectedEs256.bstr() + byteArrayOf().bstr() + payload.bstr()
        val signature = CoseAlgorithm.Signature.ES256.algorithm.getJCASignatureInstance().run {
            initSign(keyPair.private)
            update(sigStructure)
            (CoseAlgorithm.Signature.ES256.algorithm.parseJCASignature(sign()) as EcdsaSignature.IndefiniteLength)
                .withCurve(ECCurve.SECP_256_R_1)
        }
        val input = cbor("84") + protectedEs256.bstr() + cbor("A0") + payload.bstr() + signature.coseBytes.bstr()

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input).getOrThrow()

        cose.protectedHeader.type shouldBe "application/test"
        cose.prepareCoseSignatureInput() shouldBe sigStructure
        cose.verify(keyPair.public) shouldBe true
        cose.serialize(ByteArraySerializer()) shouldBe input
        CoseSigned.deserialize(ByteArraySerializer(), cose.serialize(ByteArraySerializer())).getOrThrow()
            .verify(keyPair.public) shouldBe true
    }

    "COSE_Mac0 with protected header in non-Signum key order verifies and round-trips" {
        val key = Random.nextBytes(32)
        val payload = Random.nextBytes(32)
        val macStructure = cbor("8464") + "MAC0".encodeToByteArray() +
                protectedHs256.bstr() + byteArrayOf().bstr() + payload.bstr()
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
        val input = cbor("84") + protectedHs256.bstr() + cbor("A0") + payload.bstr() + mac.doFinal(macStructure).bstr()

        val cose = CoseMac.deserialize(ByteArraySerializer(), input).getOrThrow()

        cose.prepareCoseMacInput() shouldBe macStructure
        mac.doFinal(cose.prepareCoseMacInput()) shouldBe cose.tag
        cose.serialize(ByteArraySerializer()) shouldBe input
    }

    "EUDIW status list CWT verifies" {
        val cose = CoseSigned.deserialize(ByteArraySerializer(), eudiwStatusListCwt).getOrThrow()
        val leaf = cose.protectedHeader.certificateChain.shouldNotBeNull().first()
        val publicKey = CertificateFactory.getInstance("X.509").generateCertificate(leaf.inputStream()).publicKey

        cose.protectedHeader.algorithm shouldBe CoseAlgorithm.Signature.ES256
        cose.protectedHeader.type shouldBe "application/statuslist+cwt"
        cose.verify(publicKey) shouldBe true
        // input is tagged with 18 (COSE_Sign1), serialization does not add the tag
        cose.serialize(ByteArraySerializer()) shouldBe eudiwStatusListCwt.drop(1).toByteArray()
    }
}
