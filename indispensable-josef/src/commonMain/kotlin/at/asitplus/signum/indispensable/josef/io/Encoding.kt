package at.asitplus.signum.indispensable.josef.io

import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsHeader
import kotlinx.serialization.json.Json

/**
 * JSON Serializer, preconfigured with JOSE-compliant settings:
 * ```kotlin
 * prettyPrint = false
 * encodeDefaults = false
 * classDiscriminator = "type"
 * ignoreUnknownKeys = true
 * ```
 */
val joseCompliantSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
    }
}


internal fun ByteArray?.takeUnlessEmpty(): ByteArray? = this?.takeUnless { it.isEmpty() }

internal fun JweHeader.Part?.takeUnlessEmpty(): JweHeader.Part? =
    this?.takeUnless { it.toJsonObject().isEmpty() }

internal fun JwsHeader.Part?.takeUnlessEmpty(): JwsHeader.Part? =
    this?.takeUnless { it.toJsonObject().isEmpty() }


internal fun requireAbsentIfEmpty(value: ByteArray?, memberName: String) {
    require(value == null || value.isNotEmpty()) {
        "$memberName member must be absent when it would otherwise be empty"
    }
}

internal fun requireAbsentIfEmpty(header: JweHeader.Part?, memberName: String) {
    require(header == null || header.toJsonObject().isNotEmpty()) {
        "$memberName member must be absent when it would otherwise be empty"
    }
}


internal infix fun <P> P?.xor(other: P?): P? = if (this != null && other != null) {
    throw Exception("Collision")
} else this ?: other

//fun encodeToByteArray(header: JwsHeader.Part): ByteArray = header.toProtectedHeaderBytes()
//

/**
 * Replaced by [requireAbsentIfEmpty] bytearray
 */
//
///**
// * RFC 7515 requires empty protected header values to be absent rather than encoded as `{}`.
// */
//internal fun requireAbsentIfEmpty(encodedHeader: ByteArray?) {
//    require(encodedHeader == null || decodeToJsonObject(encodedHeader).isNotEmpty()) {
//        "JWS protected header must be absent when it would otherwise be empty"
//    }
//}

//private fun ByteArray.toProtectedHeaderJsonObject(): JsonObject =


//fun decodeFromByteArray(encodedHeader: ByteArray): JwsHeader.Part = encodedHeader.toProtectedHeaderPart()

//fun decodeToJsonObject(encodedHeader: ByteArray): JsonObject = joseCompliantSerializer.decodeFromString(encodedHeader.decodeToString())

//fun encodeToByteArray(header: JweHeader.Part): ByteArray = header.toProtectedHeaderBytes()

///**
// * RFC 7516 requires empty protected header values to be absent rather than encoded as `{}`.
// */
//fun encodeToByteArrayOrNull(header: JweHeader.Part?): ByteArray? =
//    header?.takeUnless { it.toJsonObject().isEmpty() }?.toProtectedHeaderBytes()

///**
// * RFC 7516 requires empty protected header values to be absent rather than encoded as `{}`.
// */
//internal fun requireAbsentIfEmpty(encodedHeader: ByteArray?) {
//    require(encodedHeader == null || decodeToJsonObject(encodedHeader).isNotEmpty()) {
//        "JWE protected header must be absent when it would otherwise be empty"
//    }
//}

//fun decodeFromByteArray(encodedHeader: ByteArray): JweHeader.Part = encodedHeader.toProtectedHeaderPart()

//fun decodeToJsonObject(encodedHeader: ByteArray): JsonObject = joseCompliantSerializer.decodeFromString(encodedHeader.decodeToString())


//private fun ByteArray.toProtectedHeaderJsonObject(): JsonObject =
//    joseCompliantSerializer.decodeFromString(decodeToString())
