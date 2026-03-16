package at.asitplus.signum.indispensable.josef

import at.asitplus.nonFatalOrThrow
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestCompartment
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

private val generalVectorJson = """
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

private val generalVectorSource = joseCompliantSerializer.decodeFromString(JsonObject.serializer(), generalVectorJson)
private val generalVectorPayload = generalVectorSource[JWS.SerialNames.PAYLOAD]!!.jsonPrimitive.content
private val generalVectorSignatures = generalVectorSource[JWS.SerialNames.SIGNATURES]!!.jsonArray

val JwsSerializerTest by testSuite {
    "general JWS keeps vector bytes stable through serialization and flattening" {
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)

        general.signatureElements.size shouldBe 2
        general.jwsHeaders[0].algorithm shouldBe JwsAlgorithm.Signature.RS256
        general.jwsHeaders[1].algorithm shouldBe JwsAlgorithm.Signature.ES256
        general.signatures[0].shouldBeInstanceOf<CryptoSignature.RSA>()
        general.signatures[1].shouldBeInstanceOf<CryptoSignature.EC.DefiniteLength>()

        general.signatureElements.forEachIndexed { index, signatureElement ->
            val sourceSignature = generalVectorSignatures[index].jsonObject
            val protectedHeaderBase64 = sourceSignature[JWS.SerialNames.PROTECTED]!!.jsonPrimitive.content
            val signatureBase64 = sourceSignature[JWS.SerialNames.SIGNATURE]!!.jsonPrimitive.content

            signatureElement.plainProtectedHeader shouldBe protectedHeaderBase64.decodeToByteArray(Base64UrlStrict)
            signatureElement.plainSignature shouldBe signatureBase64.decodeToByteArray(Base64UrlStrict)
            general.signatureInputs[index].decodeToString() shouldBe "$protectedHeaderBase64.$generalVectorPayload"
        }

        val reserialized = joseCompliantSerializer.encodeToString(general)

        joseCompliantSerializer.decodeFromString(JsonObject.serializer(), reserialized) shouldBe generalVectorSource
        general.toJwsFlattened().toJwsGeneral() shouldBe general
    }

    "flattened JWS keeps unprotected headers stable through serialization and general conversion" {
        val protectedHeader = JwsHeader.Part(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "protected-kid",
        )
        val unprotectedHeader = JwsHeader.Part(
            contentType = "application/example+json",
            certificateUrl = "https://example.com/cert.pem",
        )
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        val plainProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(protectedHeader)
        var capturedAlgorithm: JwsAlgorithm? = null
        var capturedSignatureInput: ByteArray? = null

        val flattened = JwsFlattened(
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            payload = payload,
        ) { algorithm, signatureInput ->
            capturedAlgorithm = algorithm
            capturedSignatureInput = signatureInput
            byteArrayOf(1, 2, 3, 4)
        }

        capturedAlgorithm shouldBe JwsHeader.fromParts(protectedHeader, unprotectedHeader).algorithm
        capturedSignatureInput shouldBe JWS.getSignatureInput(plainProtectedHeader, payload)

        val serialized = joseCompliantSerializer.encodeToString(flattened)
        val reparsed = joseCompliantSerializer.decodeFromString<JwsFlattened>(serialized)

        reparsed shouldBe flattened
        with(joseCompliantSerializer) {
            decodeFromString<JsonObject>(serialized) shouldBe decodeFromString<JsonObject>(encodeToString(reparsed))
        }
        val general = listOf(flattened).toJwsGeneral()

        general.payload shouldBe payload
        general.jwsHeaders[0] shouldBe flattened.jwsHeader
        general.signatures[0] shouldBe flattened.signature
        general.signatureInputs[0] shouldBe flattened.signatureInput
        general.toJwsFlattened() shouldBe listOf(flattened)
    }

    "compact JWS keeps its exact string form and round-trips through flattened" {
        val compactString = compactSerializationAt(0)
        val compact = JwsCompact(compactString)

        compact.jwsHeader.algorithm shouldBe JwsAlgorithm.Signature.RS256
        compact.signature.shouldBeInstanceOf<CryptoSignature.RSA>()
        compact.toString() shouldBe compactString

        val serialized = joseCompliantSerializer.encodeToString(JwsCompactStringSerializer, compact)

        serialized shouldBe "\"$compactString\""
        joseCompliantSerializer.decodeFromString(JwsCompactStringSerializer, serialized) shouldBe compact

        val flattened = compact.toJwsFlattened()

        flattened.signatureInput shouldBe compact.signatureInput
        flattened.toJwsCompact() shouldBe compact
    }

    "compact JWS invoke methods round-trip as three base64url segments" {
        val compactPattern = Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")
        val compact = JwsCompact.invoke(
            protectedHeader = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
                type = "application/example+jws",
            ),
            payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray(),
        ) { _, _ ->
            byteArrayOf(1, 2, 3, 4)
        }

        val serialized = compact.toString()
        val reparsed = JwsCompact(serialized)

        compactPattern.matches(serialized) shouldBe true
        reparsed shouldBe compact
        reparsed.toString() shouldBe serialized

        val jsonString = joseCompliantSerializer.encodeToString(JwsCompactStringSerializer, compact)
            .removeSurrounding("\"")
        compactPattern.matches(jsonString) shouldBe true
    }

    "general to flattened to compact preserves each single-signature view" {
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)
        val flattened = general.toJwsFlattened()

        flattened.size shouldBe general.signatureElements.size
        flattened.forEachIndexed { index, entry ->
            entry.jwsHeader shouldBe general.jwsHeaders[index]
            entry.signature shouldBe general.signatures[index]
            entry.signatureInput shouldBe general.signatureInputs[index]
            entry.toJwsCompact().toString() shouldBe compactSerializationAt(index)
        }
    }

    "appendSignature matches list-to-general conversion" {
        val payload = """{"nonce":"1234"}""".encodeToByteArray()
        val first = flattenedSample(
            protectedHeader = JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
            ),
            payload = payload,
            plainSignature = byteArrayOf(0x01),
        )
        val second = flattenedSample(
            protectedHeader = JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.ES256,
                keyId = "kid-2",
            ),
            payload = payload,
            plainSignature = ByteArray(64) { (it + 1).toByte() },
        )

        val appended = JwsGeneral(listOf(first)).appendSignature(second)

        appended.toJwsFlattened() shouldBe listOf(first, second)
        appended shouldBe listOf(first, second).toJwsGeneral()
    }

    "general conversions reject empty and mismatched flattened inputs" {
        val first = flattenedSample(
            protectedHeader = JwsHeader.Part(algorithm = JwsAlgorithm.Signature.RS256),
            payload = "payload-1".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )
        val second = flattenedSample(
            protectedHeader = JwsHeader.Part(algorithm = JwsAlgorithm.Signature.RS256),
            payload = "payload-2".encodeToByteArray(),
            plainSignature = byteArrayOf(2),
        )

        val emptyResult = runCatching { emptyList<JwsFlattened>().toJwsGeneral() }
        val listMismatchResult = runCatching { listOf(first, second).toJwsGeneral() }
        val appendMismatchResult = runCatching { JwsGeneral(listOf(first)).appendSignature(second) }

        emptyResult.isSuccess shouldBe false
        emptyResult.shouldBeFailure() shouldBe IllegalArgumentException("General JWS requires at least one signature")

        listMismatchResult.isSuccess shouldBe false
        listMismatchResult.shouldBeFailure() shouldBe
                IllegalArgumentException("Additional signed JWS payload must match existing payload")

        appendMismatchResult.isSuccess shouldBe false
        appendMismatchResult.shouldBeFailure() shouldBe
                IllegalArgumentException("Additional signed JWS payload must match existing payload")
    }

    "compact conversion rejects missing protected header and malformed compact strings" {
        val missingProtectedHeader = JwsFlattened(
            plainProtectedHeader = null,
            unprotectedHeader = JwsHeader.Part(keyId = "kid-1", algorithm = JwsAlgorithm.Signature.RSA.RS256),
            payload = "payload".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )

        val missingHeaderResult = runCatching { missingProtectedHeader.toJwsCompact() }
        val missingPartResult = runCatching { JwsCompact("a.b") }
        val extraPartResult = runCatching { JwsCompact("a.b.c.d") }
        val invalidBase64Result = runCatching { JwsCompact("!!.e30.AQ") }

        missingHeaderResult.isSuccess shouldBe false
        missingHeaderResult.shouldBeFailure().shouldBeInstanceOf<IllegalArgumentException>()

        missingPartResult.isSuccess shouldBe false
        missingPartResult.shouldBeFailure().message.shouldContain("expected 3 parts, got 2")

        extraPartResult.isSuccess shouldBe false
        extraPartResult.shouldBeFailure().message.shouldContain("expected 3 parts, got 4")

        invalidBase64Result.isSuccess shouldBe false
        invalidBase64Result.shouldBeFailure().message.shouldContain("Invalid base64url content")
    }

    "raw-signature decoding rejects MAC algorithms" {
        val result = runCatching {
            JWS.getSignature(JwsAlgorithm.MAC.HS256, byteArrayOf(1, 2, 3))
        }

        result.isSuccess shouldBe false
        result.shouldBeFailure().message.shouldContain("Unsupported algorithm")
    }

    "signature and general equality include unprotected headers" {
        val protectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(
            JwsHeader.Part(algorithm = JwsAlgorithm.Signature.RS256)
        )
        val signatureA = SignatureElement(
            plainSignature = byteArrayOf(1),
            plainProtectedHeader = protectedHeader,
            unprotectedHeader = JwsHeader.Part(keyId = "kid-a"),
        )
        val signatureB = SignatureElement(
            plainSignature = byteArrayOf(1),
            plainProtectedHeader = protectedHeader,
            unprotectedHeader = JwsHeader.Part(keyId = "kid-b"),
        )

        signatureA shouldNotBe signatureB

        val generalA = JwsGeneral(
            payload = "payload".encodeToByteArray(),
            signatureElements = listOf(signatureA),
        )
        val generalB = JwsGeneral(
            payload = "payload".encodeToByteArray(),
            signatureElements = listOf(signatureB),
        )

        generalA shouldNotBe generalB
    }

    "sealed JWS serializer preserves the concrete JWS form" {
        val compactValue = JwsCompact(compactSerializationAt(1))
        val flattenedValue = flattenedSample(
            protectedHeader = JwsHeader.Part(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
            ),
            unprotectedHeader = JwsHeader.Part(contentType = "application/example+json"),
            payload = """{"sub":"alice"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(9, 8, 7, 6),
        )
        val generalValue = listOf(flattenedValue).toJwsGeneral()

        val compactDecoded = joseCompliantSerializer.decodeFromString<JWS>(
            joseCompliantSerializer.encodeToString(JWS.serializer(), compactValue)
        ).shouldBeInstanceOf<JwsCompact>()
        val flattenedDecoded = joseCompliantSerializer.decodeFromString<JWS>(
            joseCompliantSerializer.encodeToString(JWS.serializer(), flattenedValue)
        ).shouldBeInstanceOf<JwsFlattened>()
        val generalDecoded = joseCompliantSerializer.decodeFromString<JWS>(
            joseCompliantSerializer.encodeToString(JWS.serializer(), generalValue)
        ).shouldBeInstanceOf<JwsGeneral>()

        compactDecoded shouldBe compactValue
        flattenedDecoded shouldBe flattenedValue
        generalDecoded.toJwsFlattened() shouldBe listOf(flattenedValue)
    }

    "sealed JWS serializer rejects ambiguous and incomplete JSON objects" {
        val ambiguousResult = runCatching {
            joseCompliantSerializer.decodeFromString<JWS>(
                """{"payload":"e30","signature":"AQ","signatures":[{"signature":"AQ"}]}"""
            )
        }
        val incompleteResult = runCatching {
            joseCompliantSerializer.decodeFromString<JWS>("""{"payload":"e30"}""")
        }
        val arrayResult = runCatching {
            joseCompliantSerializer.decodeFromString<JWS>("""[1,2,3]""")
        }

        ambiguousResult.isSuccess shouldBe false
        ambiguousResult.shouldBeFailure().message.shouldContain("must not contain both")

        incompleteResult.isSuccess shouldBe false
        incompleteResult.shouldBeFailure().message.shouldContain("must contain 'signature' or 'signatures'")

        arrayResult.isSuccess shouldBe false
        arrayResult.shouldBeFailure().message.shouldContain("expected a compact string or JSON object")
    }
}

private fun compactSerializationAt(index: Int): String {
    val sourceSignature = generalVectorSignatures[index].jsonObject
    val protectedHeaderBase64 = sourceSignature[JWS.SerialNames.PROTECTED]!!.jsonPrimitive.content
    val signatureBase64 = sourceSignature[JWS.SerialNames.SIGNATURE]!!.jsonPrimitive.content
    return "$protectedHeaderBase64.$generalVectorPayload.$signatureBase64"
}

private fun flattenedSample(
    protectedHeader: JwsHeader.Part,
    payload: ByteArray,
    plainSignature: ByteArray,
    unprotectedHeader: JwsHeader.Part? = null,
): JwsFlattened = JwsFlattened(
    plainProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(protectedHeader),
    unprotectedHeader = unprotectedHeader,
    payload = payload,
    plainSignature = plainSignature,
)
