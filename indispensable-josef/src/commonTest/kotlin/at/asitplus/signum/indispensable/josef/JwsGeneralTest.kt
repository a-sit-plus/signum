package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val testvec1 = """
    {
      "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures": [
        {
          "protected": "eyJhbGciOiJSUzI1NiJ9",
          "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
        },
        {
          "protected": "eyJhbGciOiJFUzI1NiJ9",
          "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        }
      ]
    }
""".trimIndent()

val testvec2 = """
    {
      "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures": [
        {
          "protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
          "signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        },        
        {
          "protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
          "signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        }
      ]
    }
""".trimIndent()

val JwsGeneralTest by testSuite {
    "deserializes vector with correct algorithms, raw signatures, and plainSignatureInput" {
        val parsed = joseCompliantSerializer.decodeFromString<JwsGeneral<JsonObject>>(testvec1)
        val source = joseCompliantSerializer.decodeFromString(JsonObject.serializer(), testvec1)
        val payloadPart = source["payload"]!!.jsonPrimitive.content
        val sourceSignatures = source["signatures"]!!.jsonArray

        parsed.signatures.size shouldBe 2
        parsed.signatures[0].protectedHeader.algorithm shouldBe JwsAlgorithm.Signature.RS256
        parsed.signatures[1].protectedHeader.algorithm shouldBe JwsAlgorithm.Signature.ES256

        parsed.signatures[0].signature.shouldBeInstanceOf<CryptoSignature.RSA>()
        parsed.signatures[1].signature.shouldBeInstanceOf<CryptoSignature.EC.DefiniteLength>()

        parsed.signatures.forEachIndexed { index, signatureElement ->
            val sourceSignature = sourceSignatures[index].jsonObject
            val expectedProtected = sourceSignature["protected"]!!.jsonPrimitive.content
            val expectedRawSignature = sourceSignature["signature"]!!
                .jsonPrimitive
                .content
                .decodeToByteArray(Base64UrlStrict)

            signatureElement.plainSignatureInput.decodeToString() shouldBe "$expectedProtected.$payloadPart"
            signatureElement.signature.rawByteArray.contentEquals(expectedRawSignature) shouldBe true
        }
    }

    "round-trips semantically for vector 1" {
        val parsed = joseCompliantSerializer.decodeFromString<JwsGeneral<JsonObject>>(testvec1)
        val reserialized = joseCompliantSerializer.encodeToString(parsed)
        val reparsed = joseCompliantSerializer.decodeFromString<JwsGeneral<JsonObject>>(reserialized)

        reparsed shouldBe parsed
    }

    "re-serializing preserves payload and protected encoding" {
        val parsed = joseCompliantSerializer.decodeFromString<JwsGeneral<JsonObject>>(testvec1)
        val source = joseCompliantSerializer.decodeFromString(JsonObject.serializer(), testvec1)
        val reserialized = joseCompliantSerializer.encodeToString(parsed)
        val reparsed = joseCompliantSerializer.decodeFromString(JsonObject.serializer(), reserialized)

        reparsed["payload"]!!.jsonPrimitive.content shouldBe source["payload"]!!.jsonPrimitive.content

        val sourceSignatures = source["signatures"]!!.jsonArray
        val reparsedSignatures = reparsed["signatures"]!!.jsonArray
        reparsedSignatures.size shouldBe sourceSignatures.size
        reparsedSignatures.forEachIndexed { index, signatureElement ->
            signatureElement.jsonObject["protected"]!!.jsonPrimitive.content shouldBe
                    sourceSignatures[index].jsonObject["protected"]!!.jsonPrimitive.content
        }
    }

    "fails to deserialize MAC-based test vector into RawByteEncodable signatures" {
        val result = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral<JsonObject>>(testvec2)
        }

        if (result.isSuccess) throw AssertionError("Expected MAC-based vector to fail deserialization")
        result.exceptionOrNull()?.message?.shouldContain("Unsupported algorithm")
    }

    "creates JwsSigned from general JWS by signature index" {
        val parsed = joseCompliantSerializer.decodeFromString<JwsGeneral<JsonObject>>(testvec1)
        val jwsSigned0 = JwsSigned.fromJwsGeneral(parsed, 0)
        val jwsSigned1 = JwsSigned.fromJwsGeneral(parsed, 1)

        jwsSigned0.payload shouldBe parsed.payload
        jwsSigned1.payload shouldBe parsed.payload

        jwsSigned0.header shouldBe parsed.signatures[0].protectedHeader
        jwsSigned1.header shouldBe parsed.signatures[1].protectedHeader

        jwsSigned0.signature shouldBe parsed.signatures[0].signature
        jwsSigned1.signature shouldBe parsed.signatures[1].signature

        jwsSigned0.plainSignatureInput.contentEquals(parsed.signatures[0].plainSignatureInput) shouldBe true
        jwsSigned1.plainSignatureInput.contentEquals(parsed.signatures[1].plainSignatureInput) shouldBe true
    }

    "fails to create JwsSigned from general JWS with out-of-bounds index" {
        val parsed = joseCompliantSerializer.decodeFromString<JwsGeneral<JsonObject>>(testvec1)
        val result = runCatching { JwsSigned.fromJwsGeneral(parsed, 2) }

        result.isSuccess shouldBe false
        result.exceptionOrNull().shouldBeInstanceOf<IndexOutOfBoundsException>()
    }

    "accepts empty payload in compact signature input when creating general JWS" {
        val header = JwsHeader(algorithm = JwsAlgorithm.Signature.RS256)
        val plainSignatureInput = JwsSigned.prepareJwsSignatureInput(header, byteArrayOf())
        plainSignatureInput.decodeToString().endsWith(".") shouldBe true

        val signed = JwsSigned(
            header = header,
            payload = byteArrayOf(),
            signature = CryptoSignature.RSA(byteArrayOf(1)),
            plainSignatureInput = plainSignatureInput,
        )

        val general = JwsGeneral.fromSignedJws(signed)
        general.signatures.size shouldBe 1
        general.signatures.single().plainSignatureInput.decodeToString() shouldBe plainSignatureInput.decodeToString()
    }
}
