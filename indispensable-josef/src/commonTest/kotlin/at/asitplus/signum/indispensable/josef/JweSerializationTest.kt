package at.asitplus.signum.indispensable.josef

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
import kotlinx.serialization.json.*

private val compactVectorParts = listOf(
    "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ",
    "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe" +
            "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb" +
            "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV" +
            "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8" +
            "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi" +
            "6UklfCpIMfIjf7iGdXKHzg",
    "48V1_ALb6US04U3b",
    "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji" +
            "SdiwkIr3ajwQzaBtQD_A",
    "XFBoMYUZodetZdvTiFvSkQ",
)
private val compactVector = compactVectorParts.joinToString(".")

private val generalVectorJson = """
    {
      "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected": {"jku":"https://server.example.com/keys.jwks"},
      "recipients": [
        {
          "header": {"alg":"RSA1_5","kid":"2011-04-29"},
          "encrypted_key": "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
        },
        {
          "header": {"alg":"A128KW","kid":"7"},
          "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
        }
      ],
      "iv": "AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
    }
""".trimIndent()

private val flattenedVectorJson = """
    {
      "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected": {"jku":"https://server.example.com/keys.jwks"},
      "header": {"alg":"A128KW","kid":"7"},
      "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
      "iv": "AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
    }
""".trimIndent()

private val generalVectorSource = joseCompliantSerializer.decodeFromString(JsonObject.serializer(), generalVectorJson)
private val flattenedVectorSource = joseCompliantSerializer.decodeFromString(JsonObject.serializer(), flattenedVectorJson)

val JweSerializerTest by testSuite(compartment = { TestCompartment.Sequential }) {
    "compact JWE keeps RFC 7516 vector stable and round-trips through flattened" {
        val compact = JweCompact(compactVector)

        compact.toString() shouldBe compactVector
        compact.plainProtectedHeader shouldBe compactVectorParts[0].decodeToByteArray(Base64UrlStrict)
        compact.encryptedKey shouldBe compactVectorParts[1].decodeToByteArray(Base64UrlStrict)
        compact.initializationVector shouldBe compactVectorParts[2].decodeToByteArray(Base64UrlStrict)
        compact.ciphertext shouldBe compactVectorParts[3].decodeToByteArray(Base64UrlStrict)
        compact.authenticationTag shouldBe compactVectorParts[4].decodeToByteArray(Base64UrlStrict)
        compact.jweHeader.algorithm shouldBe JweAlgorithm.UNKNOWN("RSA-OAEP")
        compact.jweHeader.encryption shouldBe JweEncryption.A256GCM
        compact.additionalAuthenticatedData.decodeToString() shouldBe compactVectorParts[0]

        val serialized = joseCompliantSerializer.encodeToString(JweCompactStringSerializer, compact)

        serialized shouldBe "\"$compactVector\""
        joseCompliantSerializer.decodeFromString(JweCompactStringSerializer, serialized) shouldBe compact
        compact.toJweFlattened().toJweCompact() shouldBe compact
    }

    "general JSON JWE keeps RFC 7516 vector stable through serialization and flattening" {
        val general = joseCompliantSerializer.decodeFromString<JweGeneral>(generalVectorJson)

        general.recipientElements.size shouldBe 2
        general.jweHeaders[0].algorithm shouldBe JweAlgorithm.UNKNOWN("RSA1_5")
        general.jweHeaders[0].encryption shouldBe JweEncryption.A128CBC_HS256
        general.jweHeaders[1].algorithm shouldBe JweAlgorithm.A128KW
        general.jweHeaders[1].encryption shouldBe JweEncryption.A128CBC_HS256
        general.additionalAuthenticatedDataInput.decodeToString() shouldBe "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"

        val reserialized = joseCompliantSerializer.encodeToString(general)

        joseCompliantSerializer.decodeFromString(JsonObject.serializer(), reserialized) shouldBe generalVectorSource
        general.toJweFlattened().toJweGeneral() shouldBe general
    }

    "flattened JSON JWE keeps RFC 7516 vector stable through general conversion" {
        val flattened = joseCompliantSerializer.decodeFromString<JweFlattened>(flattenedVectorJson)

        flattened.jweHeader.algorithm shouldBe JweAlgorithm.A128KW
        flattened.jweHeader.encryption shouldBe JweEncryption.A128CBC_HS256

        val reserialized = joseCompliantSerializer.encodeToString(flattened)

        joseCompliantSerializer.decodeFromString(JsonObject.serializer(), reserialized) shouldBe flattenedVectorSource
        listOf(flattened).toJweGeneral().toJweFlattened() shouldBe listOf(flattened)
    }

    "sealed JWE serializer preserves the concrete JWE form" {
        val compactValue = JweCompact(compactVector)
        val flattenedValue = joseCompliantSerializer.decodeFromString<JweFlattened>(flattenedVectorJson)
        val generalValue = joseCompliantSerializer.decodeFromString<JweGeneral>(generalVectorJson)

        val compactSerialized = joseCompliantSerializer.encodeToString(JWE.serializer(), compactValue)
        val flattenedSerialized = joseCompliantSerializer.encodeToString(JWE.serializer(), flattenedValue)
        val generalSerialized = joseCompliantSerializer.encodeToString(JWE.serializer(), generalValue)

        joseCompliantSerializer.decodeFromString<JsonElement>(compactSerialized).shouldNotContainKey("type")
        joseCompliantSerializer.decodeFromString<JsonElement>(flattenedSerialized).shouldNotContainKey("type")
        joseCompliantSerializer.decodeFromString<JsonElement>(generalSerialized).shouldNotContainKey("type")

        joseCompliantSerializer.decodeFromString<JWE>(compactSerialized).shouldBeInstanceOf<JweCompact>() shouldBe compactValue
        joseCompliantSerializer.decodeFromString<JWE>(flattenedSerialized).shouldBeInstanceOf<JweFlattened>() shouldBe flattenedValue
        joseCompliantSerializer.decodeFromString<JWE>(generalSerialized).shouldBeInstanceOf<JweGeneral>() shouldBe generalValue
    }

    "compact JWE rejects padded and malformed compact strings" {
        val padded = compactVectorParts.toMutableList()
            .also { it[2] = it[2].toPaddedBase64UrlVariant() }
            .joinToString(".")

        val paddedResult = runCatching { JweCompact(padded) }
        val missingPartResult = runCatching { JweCompact("a.b.c.d") }
        val extraPartResult = runCatching { JweCompact("a.b.c.d.e.f") }
        val invalidBase64Result = runCatching { JweCompact("!!.b.c.d.e") }

        paddedResult.isSuccess shouldBe false
        paddedResult.shouldBeFailure().message.shouldContain("Trailing = are not supported")

        missingPartResult.isSuccess shouldBe false
        missingPartResult.shouldBeFailure().message.shouldContain("expected 5 parts, got 4")

        extraPartResult.isSuccess shouldBe false
        extraPartResult.shouldBeFailure().message.shouldContain("expected 5 parts, got 6")

        invalidBase64Result.isSuccess shouldBe false
        invalidBase64Result.shouldBeFailure().message.shouldContain("Invalid base64url content")
    }

    "JSON JWE rejects padded base64url members and explicitly empty optional members" {
        val paddedProtectedHeaderResult = runCatching {
            joseCompliantSerializer.decodeFromString<JweFlattened>(
                flattenedJson(protectedHeaderBase64 = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0".toPaddedBase64UrlVariant())
            )
        }
        val paddedCiphertextResult = runCatching {
            joseCompliantSerializer.decodeFromString<JweFlattened>(
                flattenedJson(ciphertextBase64 = "AQ".toPaddedBase64UrlVariant())
            )
        }
        val emptyProtectedHeaderResult = runCatching {
            joseCompliantSerializer.decodeFromString<JweFlattened>(
                flattenedJson(
                    protectedHeaderBase64 = "e30",
                    unprotectedHeaderJson = """{"alg":"A128KW","enc":"A128GCM"}""",
                )
            )
        }
        val emptyHeaderResult = runCatching {
            joseCompliantSerializer.decodeFromString<JweFlattened>(
                flattenedJson(headerJson = "{}")
            )
        }
        val emptyEncryptedKeyResult = runCatching {
            joseCompliantSerializer.decodeFromString<JweFlattened>(
                flattenedJson(encryptedKeyBase64 = "")
            )
        }

        paddedProtectedHeaderResult.shouldBeRejectedPaddedBase64Url()
        paddedCiphertextResult.shouldBeRejectedPaddedBase64Url()
        emptyProtectedHeaderResult.shouldBeRejectedEmptyProtectedHeader()
        emptyHeaderResult.shouldBeRejectedEmptyJweMember(JWE.SerialNames.HEADER)
        emptyEncryptedKeyResult.shouldBeRejectedEmptyJweMember(JWE.SerialNames.ENCRYPTED_KEY)
    }

    "JWE JSON header fragments reject duplicate parameter names" {
        val duplicateResult = runCatching {
            joseCompliantSerializer.decodeFromString<JweFlattened>(
                flattenedJson(headerJson = """{"alg":"A128KW"}""")
            )
        }

        duplicateResult.isSuccess shouldBe false
        duplicateResult.shouldBeFailure().message.shouldContain("Duplicate keys")
    }

    "general conversions reject empty and mismatched flattened inputs" {
        val first = flattenedSample(ciphertext = byteArrayOf(1), encryptedKey = byteArrayOf(2))
        val second = flattenedSample(ciphertext = byteArrayOf(9), encryptedKey = byteArrayOf(2))

        val emptyResult = runCatching { emptyList<JweFlattened>().toJweGeneral() }
        val mismatchResult = runCatching { listOf(first, second).toJweGeneral() }
        val appendMismatchResult = runCatching { JweGeneral(listOf(first)).appendRecipient(second) }

        emptyResult.isSuccess shouldBe false
        emptyResult.shouldBeFailure() shouldBe IllegalArgumentException("General JWE requires at least one recipient")

        mismatchResult.isSuccess shouldBe false
        mismatchResult.shouldBeFailure().message.shouldContain("must match existing content")

        appendMismatchResult.isSuccess shouldBe false
        appendMismatchResult.shouldBeFailure().message.shouldContain("must match existing content")
    }

    "compact conversion rejects JSON-only JWE members" {
        val protectedHeader = JweProtectedHeaderSerializer.encodeToByteArray(
            JweHeader.Part(
                algorithm = JweAlgorithm.A128KW,
                encryption = JweEncryption.A128GCM,
            )
        )
        val withSharedHeader = flattenedSample(
            plainProtectedHeader = protectedHeader,
            sharedUnprotectedHeader = JweHeader.Part(keyId = "shared"),
        )
        val withRecipientHeader = flattenedSample(
            plainProtectedHeader = protectedHeader,
            recipientUnprotectedHeader = JweHeader.Part(keyId = "recipient"),
        )
        val withAad = flattenedSample(
            plainProtectedHeader = protectedHeader,
            additionalAuthenticatedData = byteArrayOf(3),
        )

        runCatching { withSharedHeader.toJweCompact() }
            .shouldBeFailure().message.shouldContain("shared unprotected header")
        runCatching { withRecipientHeader.toJweCompact() }
            .shouldBeFailure().message.shouldContain("per-recipient unprotected header")
        runCatching { withAad.toJweCompact() }
            .shouldBeFailure().message.shouldContain("JWE AAD")
    }

    "general JSON JWE allows empty recipient object when headers are shared" {
        val general = JweGeneral(
            plainProtectedHeader = JweProtectedHeaderSerializer.encodeToByteArray(
                JweHeader.Part(
                    algorithm = JweAlgorithm.A128KW,
                    encryption = JweEncryption.A128GCM,
                )
            ),
            recipientElements = listOf(RecipientElement()),
            ciphertext = byteArrayOf(1),
        )

        general.jweHeaders.single().algorithm shouldBe JweAlgorithm.A128KW
        general.toJweFlattened().single().encryptedKey shouldBe null
        joseCompliantSerializer.decodeFromString<JsonObject>(
            joseCompliantSerializer.encodeToString(general)
        )[JWE.SerialNames.RECIPIENTS]!!.jsonArray.single().jsonObject shouldBe JsonObject(emptyMap())
    }

    "compact JWE builder passes protected header to encryptor" {
        val header = JweHeader(
            algorithm = JweAlgorithm.A128KW,
            encryption = JweEncryption.A128GCM,
            keyId = "compact",
        )
        var observedProtectedHeader: JweHeader.Part? = null
        var observedPayload: String? = null

        val compact = JweCompact(
            protectedHeader = header,
            payload = "plain",
        ) { protectedHeader, payload ->
            observedProtectedHeader = protectedHeader
            observedPayload = payload
            JWE.EncryptionOutput(
                iv = byteArrayOf(1),
                cipherText = byteArrayOf(2),
                encryptedKey = byteArrayOf(3),
                authenticationTag = byteArrayOf(4),
            )
        }

        observedProtectedHeader shouldBe header.toPart()
        observedPayload shouldBe "plain"
        JweProtectedHeaderSerializer.decodeFromByteArray(compact.plainProtectedHeader) shouldBe header.toPart()
        compact.encryptedKey shouldBe byteArrayOf(3)
        compact.initializationVector shouldBe byteArrayOf(1)
        compact.ciphertext shouldBe byteArrayOf(2)
        compact.authenticationTag shouldBe byteArrayOf(4)
    }

    "flattened JWE builder passes protected and merged unprotected headers to encryptor" {
        val protectedHeader = JweHeader.Part(encryption = JweEncryption.A128GCM)
        val sharedUnprotectedHeader = JweHeader.Part(jsonWebKeyUrl = "https://example.test/keys.jwks")
        val recipientUnprotectedHeader = JweHeader.Part(
            algorithm = JweAlgorithm.A128KW,
            keyId = "recipient",
        )
        var observedProtectedHeader: JweHeader.Part? = null
        var observedUnprotectedHeader: JweHeader.Part? = null

        val flattened = JweFlattened(
            protectedHeader = protectedHeader,
            payload = "plain",
            sharedUnprotectedHeader = sharedUnprotectedHeader,
            recipientUnprotectedHeader = recipientUnprotectedHeader,
            additionalAuthenticatedData = byteArrayOf(9),
        ) { protectedHeaderPart, unprotectedHeaderPart, payload ->
            observedProtectedHeader = protectedHeaderPart
            observedUnprotectedHeader = unprotectedHeaderPart
            payload shouldBe "plain"
            JWE.EncryptionOutput(
                iv = byteArrayOf(1),
                cipherText = byteArrayOf(2),
                encryptedKey = byteArrayOf(3),
                authenticationTag = byteArrayOf(4),
            )
        }

        observedProtectedHeader shouldBe protectedHeader
        observedUnprotectedHeader shouldBe JweHeader.Part(
            algorithm = JweAlgorithm.A128KW,
            keyId = "recipient",
            jsonWebKeyUrl = "https://example.test/keys.jwks",
        )
        flattened.jweHeader shouldBe JweHeader.fromParts(
            protectedHeader,
            sharedUnprotectedHeader,
            recipientUnprotectedHeader,
        )
        flattened.additionalAuthenticatedData shouldBe byteArrayOf(9)
        flattened.encryptedKey shouldBe byteArrayOf(3)
        flattened.initializationVector shouldBe byteArrayOf(1)
        flattened.ciphertext shouldBe byteArrayOf(2)
        flattened.authenticationTag shouldBe byteArrayOf(4)
    }

    "general JWE builder passes recipient-specific merged unprotected headers to encryptor" {
        val protectedHeader = JweHeader.Part(encryption = JweEncryption.A128GCM)
        val sharedUnprotectedHeader = JweHeader.Part(jsonWebKeyUrl = "https://example.test/keys.jwks")
        val recipientUnprotectedHeaders = listOf(
            JweHeader.Part(algorithm = JweAlgorithm.A128KW, keyId = "first"),
            JweHeader.Part(algorithm = JweAlgorithm.A192KW, keyId = "second"),
        )
        val observedUnprotectedHeaders = mutableListOf<JweHeader.Part?>()

        val general = JweGeneral(
            protectedHeader = protectedHeader,
            payload = "plain",
            sharedUnprotectedHeader = sharedUnprotectedHeader,
            recipientUnprotectedHeaders = recipientUnprotectedHeaders,
        ) { protectedHeaderPart, unprotectedHeaderPart, payload ->
            protectedHeaderPart shouldBe protectedHeader
            payload shouldBe "plain"
            observedUnprotectedHeaders += unprotectedHeaderPart
            JWE.EncryptionOutput(
                iv = byteArrayOf(1),
                cipherText = byteArrayOf(2),
                encryptedKey = byteArrayOf(unprotectedHeaderPart!!.keyId!!.length.toByte()),
                authenticationTag = byteArrayOf(4),
            )
        }

        observedUnprotectedHeaders shouldBe listOf(
            JweHeader.Part(
                algorithm = JweAlgorithm.A128KW,
                keyId = "first",
                jsonWebKeyUrl = "https://example.test/keys.jwks",
            ),
            JweHeader.Part(
                algorithm = JweAlgorithm.A192KW,
                keyId = "second",
                jsonWebKeyUrl = "https://example.test/keys.jwks",
            ),
        )
        general.recipientElements.map { it.encryptedKey } shouldBe listOf(
            byteArrayOf("first".length.toByte()),
            byteArrayOf("second".length.toByte()),
        )
        general.initializationVector shouldBe byteArrayOf(1)
        general.ciphertext shouldBe byteArrayOf(2)
        general.authenticationTag shouldBe byteArrayOf(4)
    }
}

private fun flattenedJson(
    protectedHeaderBase64: String = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0",
    unprotectedHeaderJson: String? = null,
    headerJson: String? = null,
    encryptedKeyBase64: String? = "AQ",
    initializationVectorBase64: String? = "Ag",
    ciphertextBase64: String = "Aw",
    authenticationTagBase64: String? = "BA",
): String = buildString {
    append("{\"protected\":\"")
    append(protectedHeaderBase64)
    append('"')
    unprotectedHeaderJson?.let {
        append(",\"unprotected\":")
        append(it)
    }
    headerJson?.let {
        append(",\"header\":")
        append(it)
    }
    encryptedKeyBase64?.let {
        append(",\"encrypted_key\":\"")
        append(it)
        append('"')
    }
    initializationVectorBase64?.let {
        append(",\"iv\":\"")
        append(it)
        append('"')
    }
    append(",\"ciphertext\":\"")
    append(ciphertextBase64)
    append('"')
    authenticationTagBase64?.let {
        append(",\"tag\":\"")
        append(it)
        append('"')
    }
    append('}')
}

private fun flattenedSample(
    plainProtectedHeader: ByteArray = JweProtectedHeaderSerializer.encodeToByteArray(
        JweHeader.Part(
            algorithm = JweAlgorithm.A128KW,
            encryption = JweEncryption.A128GCM,
        )
    ),
    sharedUnprotectedHeader: JweHeader.Part? = null,
    recipientUnprotectedHeader: JweHeader.Part? = null,
    encryptedKey: ByteArray? = byteArrayOf(2),
    additionalAuthenticatedData: ByteArray? = null,
    initializationVector: ByteArray? = byteArrayOf(3),
    ciphertext: ByteArray = byteArrayOf(4),
    authenticationTag: ByteArray? = byteArrayOf(5),
): JweFlattened = JweFlattened(
    plainProtectedHeader = plainProtectedHeader,
    sharedUnprotectedHeader = sharedUnprotectedHeader,
    recipientUnprotectedHeader = recipientUnprotectedHeader,
    encryptedKey = encryptedKey,
    additionalAuthenticatedData = additionalAuthenticatedData,
    initializationVector = initializationVector,
    ciphertext = ciphertext,
    authenticationTag = authenticationTag,
)

private fun String.toPaddedBase64UrlVariant(): String = when (length % 2) {
    1 -> "${this}=="
    else -> "${this}="
}

private fun Result<*>.shouldBeRejectedPaddedBase64Url() {
    isSuccess shouldBe false
    val failure = shouldBeFailure()
    failure.message.orEmpty().shouldContain("Decoding failed")
    failure.cause shouldNotBe null
    failure.cause!!.message.orEmpty().shouldContain("Trailing = are not supported")
}

private fun Result<*>.shouldBeRejectedEmptyProtectedHeader() {
    isSuccess shouldBe false
    shouldBeFailure().message.orEmpty().shouldContain("protected header must be absent")
}

private fun Result<*>.shouldBeRejectedEmptyJweMember(memberName: String) {
    isSuccess shouldBe false
    shouldBeFailure().message.orEmpty().shouldContain("'$memberName' member must be absent")
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
