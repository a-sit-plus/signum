package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement


/**
 * Wrapper for all JWS formats.
 */
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
        const val PAYLOAD = "payload"
    }

    companion object {
        fun getSignature(combinedHeader: JwsHeader, plainSignature: ByteArray): CryptoSignature.RawByteEncodable =
            when (val alg = combinedHeader.algorithm) {
                is JwsAlgorithm.Signature.EC -> CryptoSignature.EC.fromRawBytes(alg.ecCurve, plainSignature)
                is JwsAlgorithm.Signature.RSA -> CryptoSignature.RSA(plainSignature)
                else -> throw SerializationException("Unsupported algorithm for JWS signature element: $alg")
            }

        fun getCombinedHeader(unprotectedHeader: JsonObject, protectedHeader: ByteArray): JwsHeader =
            joseCompliantSerializer.decodeFromJsonElement(
                unprotectedHeader.strictUnion(
                    joseCompliantSerializer.decodeFromString(protectedHeader.decodeToString())
                )
            )

        fun getSignatureInput(protectedHeader: ByteArray, payload: ByteArray) =
            "${protectedHeader.encodeToString(Base64UrlStrict)}.${payload.encodeToString(Base64UrlStrict)}".encodeToByteArray()
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