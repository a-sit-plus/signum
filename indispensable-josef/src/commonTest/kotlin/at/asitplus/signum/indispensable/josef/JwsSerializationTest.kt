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

val JwsSerializerTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    "general JWS keeps vector bytes stable through serialization and flattening" {
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)
        val typedGeneral = general.typed<JsonObject, JwsHeader>()

        general.signatureElements.size shouldBe 2
        typedGeneral.wrappedHeaders[0].header.algorithm shouldBe JwsAlgorithm.Signature.RS256
        typedGeneral.wrappedHeaders[1].header.algorithm shouldBe JwsAlgorithm.Signature.ES256
        typedGeneral.signatures[0].shouldBeInstanceOf<RsaSignature>()
        typedGeneral.signatures[1].shouldBeInstanceOf<EcdsaSignature.DefiniteLength>()

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
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        val plainProtectedHeader = wrappedHeader.toProtectedHeader()
        var capturedSignatureInput: ByteArray? = null

        val flattened = JwsFlattened.invoke(
            wrappedHeader = wrappedHeader,
            payload = payload,
        ) { signatureInput ->
            capturedSignatureInput = signatureInput
            byteArrayOf(1, 2, 3, 4)
        }

        capturedSignatureInput shouldBe JWS.getSignatureInput(plainProtectedHeader, payload)

        val serialized = joseCompliantSerializer.encodeToString(flattened)
        val reparsed = joseCompliantSerializer.decodeFromString<JwsFlattened>(serialized)
        val typedReparsed = reparsed.typed<JsonObject, JwsHeader>()

        reparsed shouldBe flattened
        typedReparsed.wrappedHeader shouldBe JwsHeaderWrapped(header, unprotectedMembers)
        flattened.protectedHeader shouldBe plainProtectedHeader.toProtectedHeaderJsonObject()
        with(joseCompliantSerializer) {
            decodeFromString<JsonObject>(serialized) shouldBe decodeFromString<JsonObject>(encodeToString(reparsed))
        }
        val general = listOf(flattened).toJwsGeneral()
        val typedGeneral = general.typed<JsonObject, JwsHeader>()

        general.plainPayload shouldBe payload
        typedGeneral.wrappedHeaders[0] shouldBe typedReparsed.wrappedHeader
        typedGeneral.signatures[0] shouldBe typedReparsed.signature
        general.signatureInputs[0] shouldBe flattened.signatureInput
        general.signatureElements.single().plainProtectedHeader shouldBe flattened.plainProtectedHeader
        general.signatureElements.map { it.plainProtectedHeader } shouldBe listOf(flattened.plainProtectedHeader)
        general.toJwsFlattened() shouldBe listOf(flattened)
    }

    "general JWS preserves per-signature member placement through serialization" {
        val payload = """{"iss":"https://issuer.example","sub":"alice"}""".encodeToByteArray()
        val firstHeader = JwsHeaderWrapped(
            header = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                keyId = "kid-1",
                contentType = "application/example+json",
            ),
            unprotectedMembers = linkedSetOf(
                JwsHeader.SerialNames.CONTENT_TYPE,
                JwsHeader.SerialNames.KEY_ID,
            ),
        )
        val secondHeader = JwsHeaderWrapped(
            header = JwsHeader(
                algorithm = JwsAlgorithm.Signature.RS256,
                type = "application/example+jws",
                keyId = "kid-2",
            ),
            unprotectedMembers = setOf(JwsHeader.SerialNames.TYPE),
        )
        val general = listOf(
            flattenedSample(firstHeader, payload, byteArrayOf(1)),
            flattenedSample(secondHeader, payload, byteArrayOf(2)),
        ).toJwsGeneral()

        val reparsed = joseCompliantSerializer.decodeFromString<JwsGeneral>(
            joseCompliantSerializer.encodeToString(general)
        )
        val typedReparsed = reparsed.typed<JsonObject, JwsHeader>()
        val typedFlattened = reparsed.toJwsFlattened().map { it.typed<JsonObject, JwsHeader>() }

        reparsed shouldBe general
        typedReparsed.wrappedHeaders shouldBe listOf(firstHeader, secondHeader)
        typedFlattened.map { it.wrappedHeader } shouldBe listOf(firstHeader, secondHeader)
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
        val wrappedHeader = JwsHeaderWrapped(header, unprotectedMembers)
        val unprotectedHeader = wrappedHeader.toUnprotectedHeader()
        val conformantWithoutProtected = JwsFlattened(
            plainProtectedHeader = null,
            unprotectedHeader = unprotectedHeader,
            plainPayload = payload,
            plainSignature = byteArrayOf(1, 2, 3, 4),
        )
        var capturedSignatureInput: ByteArray? = null

        val flattened = JwsFlattened(
            wrappedHeader = wrappedHeader,
            payload = payload,
        ) { signatureInput ->
            capturedSignatureInput = signatureInput
            byteArrayOf(1, 2, 3, 4)
        }
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
        generalJson[JWS.SerialNames.SIGNATURES]!!
            .jsonArray
            .single()
            .shouldNotContainKey(JWS.SerialNames.PROTECTED)
    }

    "compact JWS keeps its exact string form and round-trips through flattened" {
        val compactString = compactSerializationAt(0)
        val compact = JwsCompact(compactString)
        val typedCompact = compact.typed<JsonObject, JwsHeader>()

        typedCompact.wrappedHeader.header.algorithm shouldBe JwsAlgorithm.Signature.RS256
        typedCompact.signature.shouldBeInstanceOf<RsaSignature>()
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
        val canonical = JwsCompact.invoke(
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
        val typedFlattened = flattened.typed<JsonObject, JwsHeader>()
        val typedGeneral = general.typed<JsonObject, JwsHeader>()

        listOf(typedFlattened.wrappedHeader, typedGeneral.wrappedHeaders.single()).forEach { wrappedHeader ->
            wrappedHeader.header.algorithm shouldBe JwsAlgorithm.Signature.RS256
            wrappedHeader.unprotectedMembers shouldBe setOf("nonce")
            wrappedHeader.effectiveUnprotectedMembers shouldBe emptySet()
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
        val compact = JwsCompact("$encodedProtectedHeader.e30.AQ")
        val flattened = joseCompliantSerializer.decodeFromString<JwsFlattened>(
            flattenedJson(protectedHeaderBase64 = encodedProtectedHeader)
        )
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral>(
            generalJson(protectedHeaderBase64 = encodedProtectedHeader)
        )

        compact.plainProtectedHeader shouldBe expectedProtectedHeader
        flattened.plainProtectedHeader shouldBe expectedProtectedHeader
        general.signatureElements.single().plainProtectedHeader shouldBe expectedProtectedHeader
    }

    "general to flattened to compact preserves each single-signature view" {
        val general = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)
        val flattened = general.toJwsFlattened()
        val typedGeneral = general.typed<JsonObject, JwsHeader>()
        val typedFlattened = flattened.map { it.typed<JsonObject, JwsHeader>() }

        flattened.size shouldBe general.signatureElements.size
        flattened.forEachIndexed { index, entry ->
            typedFlattened[index].wrappedHeader shouldBe typedGeneral.wrappedHeaders[index]
            typedFlattened[index].signature shouldBe typedGeneral.signatures[index]
            entry.signatureInput shouldBe general.signatureInputs[index]
            entry.toJwsCompact().toString() shouldBe compactSerializationAt(index)
        }
    }

    "appendSignature matches list-to-general conversion" {
        val payload = """{"nonce":"1234"}""".encodeToByteArray()
        val first = flattenedSample(
            wrappedHeader = JwsHeaderWrapped(
                JwsHeader(
                    algorithm = JwsAlgorithm.Signature.RS256,
                    keyId = "kid-1",
                )
            ),
            payload = payload,
            plainSignature = byteArrayOf(0x01),
        )
        val second = flattenedSample(
            wrappedHeader = JwsHeaderWrapped(
                JwsHeader(
                    algorithm = JwsAlgorithm.Signature.ES256,
                    keyId = "kid-2",
                )
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
            wrappedHeader = JwsHeaderWrapped(
                JwsHeader(algorithm = JwsAlgorithm.Signature.RS256)
            ),
            payload = "payload-1".encodeToByteArray(),
            plainSignature = byteArrayOf(1),
        )
        val second = flattenedSample(
            wrappedHeader = JwsHeaderWrapped(
                JwsHeader(algorithm = JwsAlgorithm.Signature.RS256)
            ),
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
        invalidBase64Result.shouldBeFailure().shouldBeInstanceOf<kotlinx.serialization.SerializationException>()
    }

    "raw-signature decoding rejects MAC algorithms" {
        val result = runCatching {
            JWS.getSignature(JwsAlgorithm.MAC.HS256, byteArrayOf(1, 2, 3))
        }

        result.isSuccess shouldBe false
        result.shouldBeFailure().message.shouldContain("Unsupported algorithm")
    }

    "signature and general equality include unprotected headers" {
        val protectedHeader = JwsHeaderWrapped(JwsHeader(algorithm = JwsAlgorithm.Signature.RS256))
            .toProtectedHeader()
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
            wrappedHeader = JwsHeaderWrapped(
                header = JwsHeader(
                    algorithm = JwsAlgorithm.Signature.RS256,
                    type = "application/example+jws",
                    contentType = "application/example+json",
                ),
                unprotectedMembers = setOf(JwsHeader.SerialNames.CONTENT_TYPE),
            ),
            payload = """{"sub":"alice"}""".encodeToByteArray(),
            plainSignature = byteArrayOf(9, 8, 7, 6),
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
