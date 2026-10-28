package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val JwsRawSerializerTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    "signing input matches RFC 7515 Appendix A.1.1 with the protected header first" {
        // Preserve the exact CRLF and spaces from https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1.1.
        val protectedHeader = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}".encodeToByteArray()
        val payload = ("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n " +
                "\"http://example.com/is_root\":true}").encodeToByteArray()
        val encodedHeader = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        val encodedPayload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

        JwsRaw.getSignatureInput(protectedHeader, payload) shouldBe "$encodedHeader.$encodedPayload".encodeToByteArray()
        JwsRaw.getSignatureInput(null, payload) shouldBe ".$encodedPayload".encodeToByteArray()
    }

    "general JWS keeps vector bytes stable through serialization and flattening" {
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(generalVectorJson)
        val typedGeneral = general.typed<JwsHeaderMonolith, JsonObject>()

        general.signatureElements.size shouldBe 2
        typedGeneral.wrappedHeaders[0].header.algorithm shouldBe JwsAlgorithm.Signature.RS256
        typedGeneral.wrappedHeaders[1].header.algorithm shouldBe JwsAlgorithm.Signature.ES256
        typedGeneral.signatures[0].shouldBeInstanceOf<RsaSignature>()
        typedGeneral.signatures[1].shouldBeInstanceOf<EcdsaSignature.DefiniteLength>()

        general.signatureElements.forEachIndexed { index, signatureElement ->
            val sourceSignature = generalVectorSignatures[index].jsonObject
            val protectedHeaderBase64 = sourceSignature[JwsRaw.SerialNames.PROTECTED]!!.jsonPrimitive.content
            val signatureBase64 = sourceSignature[JwsRaw.SerialNames.SIGNATURE]!!.jsonPrimitive.content

            signatureElement.plainProtectedHeader shouldBe protectedHeaderBase64.decodeToByteArray(Base64UrlStrict)
            signatureElement.plainSignature shouldBe signatureBase64.decodeToByteArray(Base64UrlStrict)
            general.signatureInputs[index].decodeToString() shouldBe "$protectedHeaderBase64.$generalVectorPayload"
        }

        val reserialized = joseCompliantSerializer.encodeToString(general)

        joseCompliantSerializer.decodeFromString(JsonObject.serializer(), reserialized) shouldBe generalVectorSource
        general.toFlattened().toGeneral() shouldBe general
    }

    "flattened JWS keeps unprotected headers stable through serialization and general conversion" {
        val unprotectedMembers = setOf(
            JwsHeaderMonolith.SerialNames.CONTENT_TYPE,
            JwsHeaderMonolith.SerialNames.CERTIFICATE_URL,
        )
        val header = JwsHeaderMonolith(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "protected-kid",
            contentType = "application/example+json",
            certificateUrl = "https://example.com/cert.pem",
        )
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        val plainProtectedHeader = wrappedHeader.protectedHeader
        val flattened = flattenedSample(
            wrappedHeader = wrappedHeader,
            payload = payload,
            plainSignature = byteArrayOf(1, 2, 3, 4),
        )

        val serialized = joseCompliantSerializer.encodeToString(flattened)
        val reparsed = joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(serialized)
        val typedReparsed = reparsed.typed<JwsHeaderMonolith, JsonObject>()

        reparsed shouldBe flattened
        typedReparsed.wrappedHeader shouldBe JwsHeaderWrapped(header, unprotectedMembers)
        flattened.protectedHeader shouldBe plainProtectedHeader.toProtectedHeaderJsonObject()
        with(joseCompliantSerializer) {
            decodeFromString<JsonObject>(serialized) shouldBe decodeFromString<JsonObject>(encodeToString(reparsed))
        }
        val general = listOf(flattened).toGeneral()
        val typedGeneral = general.typed<JwsHeaderMonolith, JsonObject>()

        general.plainPayload shouldBe payload
        typedGeneral.wrappedHeaders[0] shouldBe typedReparsed.wrappedHeader
        typedGeneral.signatures[0] shouldBe typedReparsed.signature
        general.signatureInputs[0] shouldBe flattened.signatureInput
        general.signatureElements.single().plainProtectedHeader shouldBe flattened.plainProtectedHeader
        general.signatureElements.map { it.plainProtectedHeader } shouldBe listOf(flattened.plainProtectedHeader)
        general.toFlattened() shouldBe listOf(flattened)
    }

    "general JWS preserves per-signature member placement through serialization" {
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        val firstHeader = JwsHeaderWrapped(
            header = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
                contentType = "application/example+json",
            ),
            unprotectedMembers = linkedSetOf(
                JwsHeaderMonolith.SerialNames.CONTENT_TYPE,
                JwsHeaderMonolith.SerialNames.KEY_ID,
            ),
        )
        val secondHeader = JwsHeaderWrapped(
            header = JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
                keyId = "kid-2",
            ),
            unprotectedMembers = setOf(JwsHeaderMonolith.SerialNames.TYPE),
        )
        val general = listOf(
            flattenedSample(firstHeader, payload, byteArrayOf(1)),
            flattenedSample(secondHeader, payload, byteArrayOf(2)),
        ).toGeneral()

        val reparsed = joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(
            joseCompliantSerializer.encodeToString(general)
        )
        val typedReparsed = reparsed.typed<JwsHeaderMonolith, JsonObject>()
        val typedFlattened = reparsed.toFlattened().map { it.typed<JwsHeaderMonolith, JsonObject>() }

        reparsed shouldBe general
        typedReparsed.wrappedHeaders shouldBe listOf(firstHeader, secondHeader)
        typedFlattened.map { it.wrappedHeader } shouldBe listOf(firstHeader, secondHeader)
    }

    "absent protected header stays omitted through flattened/general serialization" {
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        val flattened = JwsFlattened.Raw(
            plainProtectedHeader = null,
            unprotectedHeader = JsonObject(mapOf("alg" to JsonPrimitive("RS256"), "kid" to JsonPrimitive("kid-1"))),
            plainPayload = payload,
            plainSignature = byteArrayOf(1, 2, 3, 4),
        )
        val general = listOf(flattened).toGeneral()

        val flattenedJson = joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(flattened)
        )
        flattenedJson.shouldNotContainKey(JwsRaw.SerialNames.PROTECTED)

        general.signatureElements.single().plainProtectedHeader shouldBe null
        general.signatureInputs.single() shouldBe flattened.signatureInput

        val generalJson = joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(general)
        )
        generalJson[JwsRaw.SerialNames.SIGNATURES]!!
            .jsonArray
            .single()
            .shouldNotContainKey(JwsRaw.SerialNames.PROTECTED)
    }

    "compact JWS keeps its exact string form and round-trips through flattened" {
        val compactString = compactSerializationAt(0)
        val compact = JwsCompact.Raw(compactString)
        val typedCompact = compact.typed<JwsHeaderMonolith, JsonObject>()

        typedCompact.wrappedHeader.header.algorithm shouldBe JwsAlgorithm.Signature.RS256
        typedCompact.signature.shouldBeInstanceOf<RsaSignature>()
        compact.toString() shouldBe compactString

        val serialized = joseCompliantSerializer.encodeToString(JwsCompactRawStringSerializer, compact)

        serialized shouldBe "\"$compactString\""
        joseCompliantSerializer.decodeFromString(JwsCompactRawStringSerializer, serialized) shouldBe compact

        val flattened = compact.toFlattened()

        flattened.signatureInput shouldBe compact.signatureInput
        flattened.toCompact() shouldBe compact
    }

    "compact JWS components round-trip as three base64url segments" {
        val compactPattern = Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")
        val compact = JwsCompact.Raw(
            plainProtectedHeader = JwsHeaderWrapped(JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
                type = "application/example+jws",
            )).protectedHeader,
            plainPayload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(1, 2, 3, 4),
        )

        val serialized = compact.toString()
        val reparsed = JwsCompact.Raw(serialized)

        compactPattern.matches(serialized) shouldBe true
        reparsed shouldBe compact
        reparsed.toString() shouldBe serialized

        val jsonString = joseCompliantSerializer.encodeToString(JwsCompactRawStringSerializer, compact)
            .removeSurrounding("\"")
        compactPattern.matches(jsonString) shouldBe true
    }

    "compact JWS rejects padded base64url segments" {
        val canonical = JwsCompact.Raw(
            plainProtectedHeader = JwsHeaderWrapped(JwsHeaderMonolith(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
            )).protectedHeader,
            plainPayload = "x".encodeToByteArray(),
            plainSignature = byteArrayOf(1, 2, 3, 4),
        ).toString()
        val (protectedSegment, payloadSegment, signatureSegment) = canonical.split('.')
        val nonCanonical = buildString {
            append(protectedSegment)
            append('.')
            append(payloadSegment.toPaddedBase64UrlVariant())
            append('.')
            append(signatureSegment.toPaddedBase64UrlVariant())
        }

        nonCanonical shouldNotBe canonical

        val result = runCatching { JwsCompact.Raw(nonCanonical) }

        result.isSuccess shouldBe false
        result.shouldBeFailure().message.shouldContain("Trailing = are not supported")
    }

    "flattened JSON JWS rejects padded base64url members" {
        val paddedProtectedHeaderResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(
                flattenedJson(protectedHeaderBase64 = "eyJhbGciOiJSUzI1NiJ9".toPaddedBase64UrlVariant())
            )
        }
        val paddedPayloadResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(
                flattenedJson(payloadBase64 = "e30".toPaddedBase64UrlVariant())
            )
        }
        val paddedSignatureResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(
                flattenedJson(signatureBase64 = "AQ".toPaddedBase64UrlVariant())
            )
        }

        paddedProtectedHeaderResult.shouldBeRejectedPaddedBase64Url()
        paddedPayloadResult.shouldBeRejectedPaddedBase64Url()
        paddedSignatureResult.shouldBeRejectedPaddedBase64Url()
    }

    "general JSON JWS rejects padded base64url members" {
        val paddedPayloadResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(
                generalJson(payloadBase64 = "e30".toPaddedBase64UrlVariant())
            )
        }
        val paddedProtectedHeaderResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(
                generalJson(protectedHeaderBase64 = "eyJhbGciOiJSUzI1NiJ9".toPaddedBase64UrlVariant())
            )
        }
        val paddedSignatureResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(
                generalJson(signatureBase64 = "AQ".toPaddedBase64UrlVariant())
            )
        }

        paddedPayloadResult.shouldBeRejectedPaddedBase64Url()
        paddedProtectedHeaderResult.shouldBeRejectedPaddedBase64Url()
        paddedSignatureResult.shouldBeRejectedPaddedBase64Url()
    }

    "flattened and general JSON JWS reject explicitly empty protected headers" {
        val flattenedResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(
                flattenedJson(
                    protectedHeaderBase64 = "e30",
                    headerJson = """{"alg":"RS256","kid":"kid-1"}""",
                )
            )
        }
        val generalResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(
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

        val flattened = joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(flattenedJson)
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(generalJson)
        val typedFlattened = flattened.typed<JwsHeaderMonolith, JsonObject>()
        val typedGeneral = general.typed<JwsHeaderMonolith, JsonObject>()

        listOf(typedFlattened.wrappedHeader, typedGeneral.wrappedHeaders.single()).forEach { wrappedHeader ->
            wrappedHeader.header.algorithm shouldBe JwsAlgorithm.Signature.RS256
            wrappedHeader shouldBe JwsHeaderWrapped(wrappedHeader.header)
            wrappedHeader.hashCode() shouldBe JwsHeaderWrapped(wrappedHeader.header).hashCode()
        }

        joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(flattened)
        ) shouldBe joseCompliantSerializer.decodeFromString<JsonObject>(flattenedJson)
        joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(general)
        ) shouldBe joseCompliantSerializer.decodeFromString<JsonObject>(generalJson)
    }

    "raw JWS forms preserve opaque protected header bytes" {
        val encodedProtectedHeader = "bm90LWpzb24"
        val expectedProtectedHeader = "not-json".encodeToByteArray()
        val compact = JwsCompact.Raw("$encodedProtectedHeader.e30.AQ")
        val flattened = joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(
            flattenedJson(protectedHeaderBase64 = encodedProtectedHeader)
        )
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(
            generalJson(protectedHeaderBase64 = encodedProtectedHeader)
        )

        compact.plainProtectedHeader shouldBe expectedProtectedHeader
        flattened.plainProtectedHeader shouldBe expectedProtectedHeader
        general.signatureElements.single().plainProtectedHeader shouldBe expectedProtectedHeader
    }

    "general to flattened to compact preserves each single-signature view" {
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(generalVectorJson)
        val flattened = general.toFlattened()
        val typedGeneral = general.typed<JwsHeaderMonolith, JsonObject>()
        val typedFlattened = flattened.map { it.typed<JwsHeaderMonolith, JsonObject>() }

        flattened.size shouldBe general.signatureElements.size
        flattened.forEachIndexed { index, entry ->
            typedFlattened[index].wrappedHeader shouldBe typedGeneral.wrappedHeaders[index]
            typedFlattened[index].signature shouldBe typedGeneral.signatures[index]
            entry.signatureInput shouldBe general.signatureInputs[index]
            entry.toCompact().toString() shouldBe compactSerializationAt(index)
        }
    }

    "appendSignature matches list-to-general conversion" {
        val payload = """{"nonce":"1234"}""".encodeToByteArray()
        val first = flattenedSample(
            wrappedHeader = JwsHeaderWrapped(
                JwsHeaderMonolith(
                    algorithm = JwsAlgorithm.Signature.RS256,
                    keyId = "kid-1",
                )
            ),
            payload = payload,
            plainSignature = byteArrayOf(0x01),
        )
        val second = flattenedSample(
            wrappedHeader = JwsHeaderWrapped(
                JwsHeaderMonolith(
                    algorithm = JwsAlgorithm.Signature.ES256,
                    keyId = "kid-2",
                )
            ),
            payload = payload,
            plainSignature = ByteArray(64) { (it + 1).toByte() },
        )

        val appended = listOf(first).toGeneral().appendSignature(second)

        appended.toFlattened() shouldBe listOf(first, second)
        appended shouldBe listOf(first, second).toGeneral()
    }

    "general conversions reject empty and mismatched flattened inputs" {
        val first = flattenedSample(
            wrappedHeader = JwsHeaderWrapped(
                JwsHeaderMonolith(algorithm = JwsAlgorithm.Signature.RS256)
            ),
            payload = "payload-1".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )
        val second = flattenedSample(
            wrappedHeader = JwsHeaderWrapped(
                JwsHeaderMonolith(algorithm = JwsAlgorithm.Signature.RS256)
            ),
            payload = "payload-2".encodeToByteArray(),
            plainSignature = byteArrayOf(2),
        )

        val emptyResult = runCatching { emptyList<JwsFlattened.Raw>().toGeneral() }
        val listMismatchResult = runCatching { listOf(first, second).toGeneral() }
        val appendMismatchResult = runCatching { listOf(first).toGeneral().appendSignature(second) }

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
        val missingProtectedHeader = JwsFlattened.Raw(
            plainProtectedHeader = null,
            unprotectedHeader = JsonObject(
                mapOf(
                    JwsHeaderMonolith.SerialNames.KEY_ID to JsonPrimitive("kid-1"),
                    JwsHeaderMonolith.SerialNames.ALGORITHM to JsonPrimitive("RS256"),
                )
            ),
            plainPayload = "payload".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )

        val missingHeaderResult = runCatching { missingProtectedHeader.toCompact() }
        val missingPartResult = runCatching { JwsCompact.Raw("a.b") }
        val extraPartResult = runCatching { JwsCompact.Raw("a.b.c.d") }
        val invalidBase64Result = runCatching { JwsCompact.Raw("!!.e30.AQ") }

        missingHeaderResult.isSuccess shouldBe false
        missingHeaderResult.shouldBeFailure().shouldBeInstanceOf<IllegalArgumentException>()

        missingPartResult.isSuccess shouldBe false
        missingPartResult.shouldBeFailure().message.shouldContain("expected 3 parts, got 2")

        extraPartResult.isSuccess shouldBe false
        extraPartResult.shouldBeFailure().message.shouldContain("expected 3 parts, got 4")

        invalidBase64Result.isSuccess shouldBe false
        invalidBase64Result.shouldBeFailure().shouldBeInstanceOf<kotlinx.serialization.SerializationException>()
    }

    "raw-signature decoding rejects MAC algorithms" {
        val result = runCatching {
            JwsRaw.getSignature(JwsAlgorithm.MAC.HS256, byteArrayOf(1, 2, 3))
        }

        result.isSuccess shouldBe false
        result.shouldBeFailure().message.shouldContain("Unsupported algorithm")
    }

    "signature and general equality include unprotected headers" {
        val protectedHeader = JwsHeaderWrapped(JwsHeaderMonolith(algorithm = JwsAlgorithm.Signature.RS256))
            .protectedHeader
        val signatureA = SignatureElement(
            plainSignature = byteArrayOf(1),
            plainProtectedHeader = protectedHeader,
            unprotectedHeader = JsonObject(
                mapOf(JwsHeaderMonolith.SerialNames.KEY_ID to JsonPrimitive("kid-a"))
            ),
        )
        val signatureB = SignatureElement(
            plainSignature = byteArrayOf(1),
            plainProtectedHeader = protectedHeader,
            unprotectedHeader = JsonObject(
                mapOf(JwsHeaderMonolith.SerialNames.KEY_ID to JsonPrimitive("kid-b"))
            ),
        )

        signatureA shouldNotBe signatureB

        val generalA = JwsGeneral.Raw(
            plainPayload = "payload".encodeToByteArray(),
            signatureElements = listOf(signatureA),
        )
        val generalB = JwsGeneral.Raw(
            plainPayload = "payload".encodeToByteArray(),
            signatureElements = listOf(signatureB),
        )

        generalA shouldNotBe generalB
    }

    "sealed JWS serializer preserves the concrete JWS form" {
        val compactValue = JwsCompact.Raw(compactSerializationAt(1))
        val flattenedValue = flattenedSample(
            wrappedHeader = JwsHeaderWrapped(
                header = JwsHeaderMonolith(
                    algorithm = JwsAlgorithm.Signature.RS256,
                    type = "application/example+jws",
                    contentType = "application/example+json",
                ),
                unprotectedMembers = setOf(JwsHeaderMonolith.SerialNames.CONTENT_TYPE),
            ),
            payload = """{"sub":"alice"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(9, 8, 7, 6),
        )
        val generalValue = listOf(flattenedValue).toGeneral()

        val compactSerialized = joseCompliantSerializer.encodeToString(JwsRaw.serializer(), compactValue)
        val flattenedSerialized = joseCompliantSerializer.encodeToString(JwsRaw.serializer(), flattenedValue)
        val generalSerialized = joseCompliantSerializer.encodeToString(JwsRaw.serializer(), generalValue)

        joseCompliantSerializer.decodeFromString<JsonElement>(compactSerialized).shouldNotContainKey("type")
        joseCompliantSerializer.decodeFromString<JsonElement>(flattenedSerialized).shouldNotContainKey("type")
        joseCompliantSerializer.decodeFromString<JsonElement>(generalSerialized).shouldNotContainKey("type")

        val compactDecoded = joseCompliantSerializer.decodeFromString<JwsRaw>(compactSerialized)
            .shouldBeInstanceOf<JwsCompact.Raw>()
        val flattenedDecoded = joseCompliantSerializer.decodeFromString<JwsRaw>(flattenedSerialized)
            .shouldBeInstanceOf<JwsFlattened.Raw>()
        val generalDecoded = joseCompliantSerializer.decodeFromString<JwsRaw>(generalSerialized)
            .shouldBeInstanceOf<JwsGeneral.Raw>()

        compactDecoded shouldBe compactValue
        flattenedDecoded shouldBe flattenedValue
        generalDecoded.toFlattened() shouldBe listOf(flattenedValue)
    }

    "sealed JWS serializer rejects ambiguous and incomplete JSON objects" {
        val ambiguousResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsRaw>(
                """{"payload":"e30","signature":"AQ","signatures":[{"signature":"AQ"}]}"""
            )
        }
        val incompleteResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsRaw>("""{"payload":"e30"}""")
        }
        val arrayResult = runCatching {
            joseCompliantSerializer.decodeFromString<JwsRaw>("""[1,2,3]""")
        }

        ambiguousResult.isSuccess shouldBe false
        ambiguousResult.shouldBeFailure().message.shouldContain("must not contain both")

        incompleteResult.isSuccess shouldBe false
        incompleteResult.shouldBeFailure().message.shouldContain("must contain 'signature' or 'signatures'")

        arrayResult.isSuccess shouldBe false
        arrayResult.shouldBeFailure().message.shouldContain("expected a compact string or JSON object")
    }
}
