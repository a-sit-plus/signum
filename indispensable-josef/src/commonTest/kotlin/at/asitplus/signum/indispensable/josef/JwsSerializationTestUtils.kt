package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal val generalVectorJson = """
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

internal val generalVectorSource = joseCompliantSerializer.decodeFromString(JsonObject.serializer(), generalVectorJson)
internal val generalVectorPayload = generalVectorSource[JWS.SerialNames.PAYLOAD]!!.jsonPrimitive.content
internal val generalVectorSignatures = generalVectorSource[JWS.SerialNames.SIGNATURES]!!.jsonArray

internal fun compactSerializationAt(index: Int): String {
    val sourceSignature = generalVectorSignatures[index].jsonObject
    val protectedHeaderBase64 = sourceSignature[JWS.SerialNames.PROTECTED]!!.jsonPrimitive.content
    val signatureBase64 = sourceSignature[JWS.SerialNames.SIGNATURE]!!.jsonPrimitive.content
    return "$protectedHeaderBase64.$generalVectorPayload.$signatureBase64"
}

internal fun flattenedJson(
    protectedHeaderBase64: String = "eyJhbGciOiJSUzI1NiJ9",
    payloadBase64: String = "e30",
    signatureBase64: String = "AQ",
    headerJson: String? = null,
): String = """
    {"protected":"$protectedHeaderBase64","payload":"$payloadBase64","signature":"$signatureBase64"${headerJson?.let { ""","header":$it""" }.orEmpty()}}
""".trimIndent()

internal fun generalJson(
    protectedHeaderBase64: String = "eyJhbGciOiJSUzI1NiJ9",
    payloadBase64: String = "e30",
    signatureBase64: String = "AQ",
    headerJson: String? = null,
): String = """
    {"payload":"$payloadBase64","signatures":[{"protected":"$protectedHeaderBase64","signature":"$signatureBase64"${headerJson?.let { ""","header":$it""" }.orEmpty()}}]}
""".trimIndent()

internal fun flattenedSample(
    wrappedHeader: JwsHeaderWrapped<JwsHeader>,
    payload: ByteArray,
    plainSignature: ByteArray,
): JwsFlattened = JwsFlattened(
    plainProtectedHeader = wrappedHeader.toProtectedHeader()
        .takeUnless { it.toProtectedHeaderJsonObject().isEmpty() },
    unprotectedHeader = wrappedHeader.toUnprotectedHeader().takeUnless { it.isEmpty() },
    plainPayload = payload,
    plainSignature = plainSignature,
)

internal fun String.toPaddedBase64UrlVariant(): String = when (length % 2) {
    1 -> "${this}=="
    else -> "${this}="
}

internal fun Result<*>.shouldBeRejectedPaddedBase64Url() {
    isSuccess shouldBe false
    val failure = shouldBeFailure()
    failure.message.orEmpty().shouldContain("Decoding failed")
    failure.cause shouldNotBe null
    failure.cause!!.message.orEmpty().shouldContain("Trailing = are not supported")
}

internal fun Result<*>.shouldBeRejectedEmptyProtectedHeader() {
    isSuccess shouldBe false
    shouldBeFailure().message.orEmpty().shouldContain("must be absent when it would otherwise be empty")
}

internal fun JsonElement.shouldNotContainKey(key: String) {
    when (this) {
        is JsonObject -> {
            keys.contains(key) shouldBe false
            values.forEach { it.shouldNotContainKey(key) }
        }

        is JsonArray -> forEach { it.shouldNotContainKey(key) }
        else -> Unit
    }
}
