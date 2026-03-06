package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement

sealed class JWS {
    abstract val payload: ByteArray

    fun <P> getPayload(serializer: KSerializer<P>, serialFormat: SerialFormat = joseCompliantSerializer): P =
        when (serialFormat) {
            is StringFormat -> serialFormat.decodeFromString(serializer, payload.decodeToString())
            is BinaryFormat -> serialFormat.decodeFromByteArray(serializer, payload)
            else -> throw NotImplementedError("Unknown serial format $serialFormat")
        }

    /**
     * Find correct serializer at compile time
     */
    inline fun <reified P> getPayload(serialFormat: SerialFormat): P =
        getPayload(serialFormat.serializersModule.serializer(), serialFormat)

    object SerialNames {
        const val PROTECTED = "protected"
        const val HEADER = "header"
        const val SIGNATURE = "signature"
        const val SIGNATURES = "signatures"
    }
}

internal fun JsonObject?.strictUnion(other: JsonObject?): JsonObject {
    if (this == null) return other ?: JsonObject(emptyMap())
    if (other == null) return this

    val duplicates = this.keys intersect other.keys
    require(duplicates.isEmpty()) {
        "Duplicate keys: ${duplicates.joinToString()}"
    }

    return JsonObject(this + other)
}