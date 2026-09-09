package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

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
private val generalVectorPayload = generalVectorSource[JWS.SerialNames.PAYLOAD].shouldNotBeNull().jsonPrimitive.content
private val generalVectorSignatures = generalVectorSource[JWS.SerialNames.SIGNATURES].shouldNotBeNull().jsonArray

val JwsSerializerTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    "general JWS keeps vector bytes stable through serialization and flattening" {
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)
        val flattened = general.toJwsFlattened()

        general.signatureElements.size shouldBe 2
        flattened.size shouldBe general.signatureElements.size
        general.wrappedHeaders[0].header.algorithm shouldBe JwsAlgorithm.Signature.RS256
        general.wrappedHeaders[1].header.algorithm shouldBe JwsAlgorithm.Signature.ES256
        general.signatures[0].shouldBeInstanceOf<CryptoSignature.RSA>()
        general.signatures[1].shouldBeInstanceOf<CryptoSignature.EC.DefiniteLength>()

        general.signatureElements.forEachIndexed { index, signatureElement ->
            val sourceSignature = generalVectorSignatures[index].jsonObject
            val protectedHeaderBase64 = sourceSignature[JWS.SerialNames.PROTECTED].shouldNotBeNull().jsonPrimitive.content
            val signatureBase64 = sourceSignature[JWS.SerialNames.SIGNATURE].shouldNotBeNull().jsonPrimitive.content

            signatureElement.plainProtectedHeader shouldBe protectedHeaderBase64.decodeToByteArray(Base64UrlStrict)
            signatureElement.plainSignature shouldBe signatureBase64.decodeToByteArray(Base64UrlStrict)
            general.signatureInputs[index].decodeToString() shouldBe "$protectedHeaderBase64.$generalVectorPayload"

            val flattenedEntry = flattened[index]
            flattenedEntry.wrappedHeader shouldBe general.wrappedHeaders[index]
            flattenedEntry.signature shouldBe general.signatures[index]
            flattenedEntry.signatureInput shouldBe general.signatureInputs[index]
            flattenedEntry.toJwsCompact().toString() shouldBe compactSerializationAt(index)
        }

        val reserialized = joseCompliantSerializer.encodeToString(general)

        joseCompliantSerializer.decodeFromString(JsonObject.serializer(), reserialized) shouldBe generalVectorSource
        flattened.toJwsGeneral() shouldBe general
    }

    "flattened JWS keeps unprotected headers stable through serialization and general conversion" {
        val unprotectedMembers = setOf(
            JwsHeader.SerialNames.CONTENT_TYPE,
            JwsHeader.SerialNames.CERTIFICATE_URL,
        )
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "protected-kid",
            contentType = "application/example+json",
            certificateUrl = "https://example.com/cert.pem",
        )
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        var capturedSignatureInput: ByteArray? = null

        val flattened = JwsFlattened(
            header = header,
            payload = payload,
            unprotectedMembers = unprotectedMembers,
        ) { signatureInput ->
            capturedSignatureInput = signatureInput
            byteArrayOf(1, 2, 3, 4)
        }
        val plainProtectedHeader = flattened.plainProtectedHeader.shouldNotBeNull()

        capturedSignatureInput shouldBe JWS.getSignatureInput(plainProtectedHeader, payload)

        val serialized = joseCompliantSerializer.encodeToString(flattened)
        val reparsed = joseCompliantSerializer.decodeFromString<JwsFlattened>(serialized)

        reparsed shouldBe flattened
        reparsed.wrappedHeader.header shouldBe header
        reparsed.wrappedHeader.unprotectedMembers shouldBe unprotectedMembers
        @Suppress("DEPRECATION")
        val deprecatedProtectedHeader = reparsed.protectedHeader
        deprecatedProtectedHeader shouldBe plainProtectedHeader.toProtectedHeaderJsonObject()
        with(joseCompliantSerializer) {
            decodeFromString<JsonObject>(serialized) shouldBe decodeFromString<JsonObject>(encodeToString(reparsed))
        }
        val general = listOf(flattened).toJwsGeneral()

        general.plainPayload shouldBe payload
        general.wrappedHeaders[0] shouldBe flattened.wrappedHeader
        general.signatures[0] shouldBe flattened.signature
        general.signatureInputs[0] shouldBe flattened.signatureInput
        @Suppress("DEPRECATION")
        val deprecatedSignatureProtectedHeader = general.signatureElements.single().protectedHeader
        @Suppress("DEPRECATION")
        val deprecatedProtectedHeaders = general.protectedHeaders
        deprecatedSignatureProtectedHeader shouldBe deprecatedProtectedHeader
        deprecatedProtectedHeaders shouldBe listOf(deprecatedProtectedHeader)
        general.toJwsFlattened() shouldBe listOf(flattened)
    }

    "general JWS preserves per-signature member placement through serialization" {
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        val firstHeader = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            keyId = "kid-1",
            contentType = "application/example+json",
        )
        val firstUnprotectedMembers = linkedSetOf(
            JwsHeader.SerialNames.CONTENT_TYPE,
            JwsHeader.SerialNames.KEY_ID,
        )
        val secondHeader = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-2",
        )
        val secondUnprotectedMembers = setOf(JwsHeader.SerialNames.TYPE)
        val general = listOf(
            flattenedSample(firstHeader, payload, byteArrayOf(1), firstUnprotectedMembers),
            flattenedSample(secondHeader, payload, byteArrayOf(2), secondUnprotectedMembers),
        ).toJwsGeneral()

        val reparsed = joseCompliantSerializer.decodeFromString<JwsGeneral>(
            joseCompliantSerializer.encodeToString(general)
        )

        reparsed shouldBe general
        reparsed.wrappedHeaders shouldBe general.wrappedHeaders
        reparsed.toJwsFlattened().map { it.wrappedHeader } shouldBe general.wrappedHeaders
    }

    "empty protected header is omitted from flattened/general JWS and signing input" {
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        val header = JwsHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            keyId = "kid-1",
        )
        val unprotectedMembers = setOf(
            JwsHeader.SerialNames.ALGORITHM,
            JwsHeader.SerialNames.KEY_ID,
        )
        var capturedSignatureInput: ByteArray? = null

        val flattened = JwsFlattened(
            header = header,
            payload = payload,
            unprotectedMembers = unprotectedMembers,
        ) { signatureInput ->
            capturedSignatureInput = signatureInput
            byteArrayOf(1, 2, 3, 4)
        }
        val conformantWithoutProtected = JwsFlattened(
            plainProtectedHeader = null,
            unprotectedHeader = flattened.unprotectedHeader,
            plainPayload = payload,
            plainSignature = byteArrayOf(1, 2, 3, 4),
        )
        val general = listOf(flattened).toJwsGeneral()

        flattened shouldBe conformantWithoutProtected
        flattened.plainProtectedHeader shouldBe null
        capturedSignatureInput shouldBe JWS.getSignatureInput(null, payload)
        flattened.signatureInput shouldBe capturedSignatureInput
        flattened.signatureInput shouldBe conformantWithoutProtected.signatureInput

        val flattenedJson = joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(flattened)
        )
        flattenedJson.shouldNotContainKey(JWS.SerialNames.PROTECTED)

        general.signatureElements.single().plainProtectedHeader shouldBe null
        general.signatureInputs.single() shouldBe conformantWithoutProtected.signatureInput

        val generalJson = joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(general)
        )
        generalJson[JWS.SerialNames.SIGNATURES].shouldNotBeNull()
            .jsonArray
            .single()
            .shouldNotContainKey(JWS.SerialNames.PROTECTED)
    }

    "compact JWS keeps its exact string form and round-trips through flattened" {
        val compactString = compactSerializationAt(0)
        val compact = JwsCompact(compactString)

        compact.wrappedHeader.header.algorithm shouldBe JwsAlgorithm.Signature.RS256
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
        val compact = JwsCompact(
            protectedHeader = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
                type = "application/example+jws",
            ),
            payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray(),
        ) {
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

    "compact JWS rejects padded base64url segments" {
        val canonical = JwsCompact(
            protectedHeader = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
            ),
            payload = "x".encodeToByteArray(),
        ) {
            byteArrayOf(1, 2, 3, 4)
        }.toString()
        val (protectedSegment, payloadSegment, signatureSegment) = canonical.split('.')
        val nonCanonical = buildString {
            append(protectedSegment)
            append('.')
            append(payloadSegment.toPaddedBase64UrlVariant())
            append('.')
            append(signatureSegment.toPaddedBase64UrlVariant())
        }

        nonCanonical shouldNotBe canonical

        val result = runCatching { JwsCompact(nonCanonical) }

        result.isSuccess shouldBe false
        result.shouldBeFailure().message.shouldContain("Trailing = are not supported")
    }

    "flattened JSON JWS rejects padded base64url members" {
        val paddedProtectedHeaderResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsFlattened>(
                flattenedJson(protectedHeaderBase64 = "eyJhbGciOiJSUzI1NiJ9".toPaddedBase64UrlVariant())
            )
        }
        val paddedPayloadResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsFlattened>(
                flattenedJson(payloadBase64 = "e30".toPaddedBase64UrlVariant())
            )
        }
        val paddedSignatureResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsFlattened>(
                flattenedJson(signatureBase64 = "AQ".toPaddedBase64UrlVariant())
            )
        }

        paddedProtectedHeaderResult.shouldBeRejectedPaddedBase64Url()
        paddedPayloadResult.shouldBeRejectedPaddedBase64Url()
        paddedSignatureResult.shouldBeRejectedPaddedBase64Url()
    }

    "general JSON JWS rejects padded base64url members" {
        val paddedPayloadResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral>(
                generalJson(payloadBase64 = "e30".toPaddedBase64UrlVariant())
            )
        }
        val paddedProtectedHeaderResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral>(
                generalJson(protectedHeaderBase64 = "eyJhbGciOiJSUzI1NiJ9".toPaddedBase64UrlVariant())
            )
        }
        val paddedSignatureResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral>(
                generalJson(signatureBase64 = "AQ".toPaddedBase64UrlVariant())
            )
        }

        paddedPayloadResult.shouldBeRejectedPaddedBase64Url()
        paddedProtectedHeaderResult.shouldBeRejectedPaddedBase64Url()
        paddedSignatureResult.shouldBeRejectedPaddedBase64Url()
    }

    "flattened and general JSON JWS reject explicitly empty protected headers" {
        val flattenedResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsFlattened>(
                flattenedJson(
                    protectedHeaderBase64 = "e30",
                    headerJson = """{"alg":"RS256","kid":"kid-1"}""",
                )
            )
        }
        val generalResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral>(
                generalJson(
                    protectedHeaderBase64 = "e30",
                    headerJson = """{"alg":"RS256","kid":"kid-1"}""",
                )
            )
        }

        flattenedResult.shouldBeRejectedEmptyProtectedHeader()
        generalResult.shouldBeRejectedEmptyProtectedHeader()
    }

    "flattened and general JSON JWS accept unmodeled unprotected header members" {
        val headerJson = """{"nonce":"nonce-value"}"""
        val flattenedJson = flattenedJson(headerJson = headerJson)
        val generalJson = generalJson(headerJson = headerJson)

        val flattened = joseCompliantSerializer.decodeFromString<JwsFlattened>(flattenedJson)
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalJson)

        listOf(flattened.wrappedHeader, general.wrappedHeaders.single()).forEach { wrappedHeader ->
            wrappedHeader.header.algorithm shouldBe JwsAlgorithm.Signature.RS256
            wrappedHeader.unprotectedMembers shouldBe setOf("nonce")
        }

        joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(flattened)
        ) shouldBe joseCompliantSerializer.decodeFromString<JsonObject>(flattenedJson)
        joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(general)
        ) shouldBe joseCompliantSerializer.decodeFromString<JsonObject>(generalJson)
    }

    "compact, flattened, and general JWS reject malformed protected header JSON" {
        val malformedProtectedHeader = "bm90LWpzb24"
        val results = listOf(
            runCatching { JwsCompact("$malformedProtectedHeader.e30.AQ") },
            runCatching {
                joseCompliantSerializer.decodeFromString<JwsFlattened>(
                    flattenedJson(protectedHeaderBase64 = malformedProtectedHeader)
                )
            },
            runCatching {
                joseCompliantSerializer.decodeFromString<JwsGeneral>(
                    generalJson(protectedHeaderBase64 = malformedProtectedHeader)
                )
            },
        )

        results.forEach { result ->
            result.isSuccess shouldBe false
            result.shouldBeFailure().shouldBeInstanceOf<SerializationException>()
        }
    }

    "appendSignature matches list-to-general conversion" {
        val payload = """{"nonce":"1234"}""".encodeToByteArray()
        val first = flattenedSample(
            header = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
            ),
            payload = payload,
            plainSignature = byteArrayOf(0x01),
        )
        val second = flattenedSample(
            header = JwsHeader(
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
            header = JwsHeader(algorithm = JwsAlgorithm.Signature.RS256),
            payload = "payload-1".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )
        val second = flattenedSample(
            header = JwsHeader(algorithm = JwsAlgorithm.Signature.RS256),
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
            unprotectedHeader = JsonObject(
                mapOf(
                    JwsHeader.SerialNames.KEY_ID to JsonPrimitive("kid-1"),
                    JwsHeader.SerialNames.ALGORITHM to JsonPrimitive("RS256"),
                )
            ),
            plainPayload = "payload".encodeToByteArray(),
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
        invalidBase64Result.shouldBeFailure().shouldBeInstanceOf<SerializationException>()
    }

    "raw-signature decoding rejects MAC algorithms" {
        val result = runCatching {
            JWS.getSignature(JwsAlgorithm.MAC.HS256, byteArrayOf(1, 2, 3))
        }

        result.isSuccess shouldBe false
        result.shouldBeFailure().message.shouldContain("Unsupported algorithm")
    }

    "signature and general equality include unprotected headers" {
        val protectedHeader = joseCompliantSerializer.encodeToString(
            JwsHeader(algorithm = JwsAlgorithm.Signature.RS256)
        ).encodeToByteArray()
        val signatureA = SignatureElement(
            plainSignature = byteArrayOf(1),
            plainProtectedHeader = protectedHeader,
            unprotectedHeader = JsonObject(
                mapOf(JwsHeader.SerialNames.KEY_ID to JsonPrimitive("kid-a"))
            ),
        )
        val signatureB = SignatureElement(
            plainSignature = byteArrayOf(1),
            plainProtectedHeader = protectedHeader,
            unprotectedHeader = JsonObject(
                mapOf(JwsHeader.SerialNames.KEY_ID to JsonPrimitive("kid-b"))
            ),
        )

        signatureA shouldNotBe signatureB

        val generalA = JwsGeneral(
            plainPayload = "payload".encodeToByteArray(),
            signatureElements = listOf(signatureA),
        )
        val generalB = JwsGeneral(
            plainPayload = "payload".encodeToByteArray(),
            signatureElements = listOf(signatureB),
        )

        generalA shouldNotBe generalB
    }

    "sealed JWS serializer preserves the concrete JWS form" {
        val compactValue = JwsCompact(compactSerializationAt(1))
        val flattenedValue = flattenedSample(
            header = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
                contentType = "application/example+json",
            ),
            payload = """{"sub":"alice"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(9, 8, 7, 6),
            unprotectedMembers = setOf(JwsHeader.SerialNames.CONTENT_TYPE),
        )
        val generalValue = listOf(flattenedValue).toJwsGeneral()

        val compactSerialized = joseCompliantSerializer.encodeToString(JWS.serializer(), compactValue)
        val flattenedSerialized = joseCompliantSerializer.encodeToString(JWS.serializer(), flattenedValue)
        val generalSerialized = joseCompliantSerializer.encodeToString(JWS.serializer(), generalValue)

        joseCompliantSerializer.decodeFromString<JsonElement>(compactSerialized).shouldNotContainKey("type")
        joseCompliantSerializer.decodeFromString<JsonElement>(flattenedSerialized).shouldNotContainKey("type")
        joseCompliantSerializer.decodeFromString<JsonElement>(generalSerialized).shouldNotContainKey("type")

        val compactDecoded = joseCompliantSerializer.decodeFromString<JWS>(compactSerialized)
            .shouldBeInstanceOf<JwsCompact>()
        val flattenedDecoded = joseCompliantSerializer.decodeFromString<JWS>(flattenedSerialized)
            .shouldBeInstanceOf<JwsFlattened>()
        val generalDecoded = joseCompliantSerializer.decodeFromString<JWS>(generalSerialized)
            .shouldBeInstanceOf<JwsGeneral>()

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
    val protectedHeaderBase64 = sourceSignature[JWS.SerialNames.PROTECTED].shouldNotBeNull().jsonPrimitive.content
    val signatureBase64 = sourceSignature[JWS.SerialNames.SIGNATURE].shouldNotBeNull().jsonPrimitive.content
    return "$protectedHeaderBase64.$generalVectorPayload.$signatureBase64"
}

private fun flattenedJson(
    protectedHeaderBase64: String = "eyJhbGciOiJSUzI1NiJ9",
    payloadBase64: String = "e30",
    signatureBase64: String = "AQ",
    headerJson: String? = null,
): String = """
    {"protected":"$protectedHeaderBase64","payload":"$payloadBase64","signature":"$signatureBase64"${headerJson?.let { ""","header":$it""" }.orEmpty()}}
""".trimIndent()

private fun generalJson(
    protectedHeaderBase64: String = "eyJhbGciOiJSUzI1NiJ9",
    payloadBase64: String = "e30",
    signatureBase64: String = "AQ",
    headerJson: String? = null,
): String = """
    {"payload":"$payloadBase64","signatures":[{"protected":"$protectedHeaderBase64","signature":"$signatureBase64"${headerJson?.let { ""","header":$it""" }.orEmpty()}}]}
""".trimIndent()

private suspend fun flattenedSample(
    header: JwsHeader,
    payload: ByteArray,
    plainSignature: ByteArray,
    unprotectedMembers: Set<String> = emptySet(),
): JwsFlattened = JwsFlattened(header, payload, unprotectedMembers) { plainSignature }

private fun String.toPaddedBase64UrlVariant(): String = when (length % 2) {
    1 -> "${this}=="
    else -> "${this}="
}

private fun Result<*>.shouldBeRejectedPaddedBase64Url() {
    isSuccess shouldBe false
    val failure = shouldBeFailure()
    failure.message.orEmpty().shouldContain("Decoding failed")
    failure.cause shouldNotBe null
    failure.cause.shouldNotBeNull().message.orEmpty().shouldContain("Trailing = are not supported")
}

private fun Result<*>.shouldBeRejectedEmptyProtectedHeader() {
    isSuccess shouldBe false
    shouldBeFailure().message.orEmpty().shouldContain("must be absent when it would otherwise be empty")
}

private fun JsonElement.shouldNotContainKey(key: String) {
    when (this) {
        is JsonObject -> {
            keys.contains(key) shouldBe false
            values.forEach { it.shouldNotContainKey(key) }
        }

        is JsonArray -> forEach { it.shouldNotContainKey(key) }
        else -> Unit
    }
}
