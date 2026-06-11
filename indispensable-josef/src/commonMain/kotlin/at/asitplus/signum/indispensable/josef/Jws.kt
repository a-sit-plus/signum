package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive


/**
 * Wrapper for all JWS formats.
 *
 * If [plainPayload] data structure is defined as part of the contact consider [JwsTyped]
 */
@Serializable(with = JwsSerializer::class)
sealed class JWS : JsonSecured {
    /**
     * Raw payload bytes.
     *
     * JWS serializers and signature-input construction base64url-encode these bytes where required.
     * Callers should not pre-encode the payload.
     */
    abstract val plainPayload: ByteArray

    fun <P> getPayload(serializer: KSerializer<P>, serialFormat: SerialFormat = joseCompliantSerializer): KmmResult<P> = runCatching {
        when (serialFormat) {
            is StringFormat -> serialFormat.decodeFromString(serializer, plainPayload.decodeToString())
            is BinaryFormat -> serialFormat.decodeFromByteArray(serializer, plainPayload)
            else -> throw NotImplementedError("Unknown serial format $serialFormat")
        }
    }.wrap()

    /**
     * Find correct serializer at compile time
     */
    inline fun <reified P> getPayload(serialFormat: SerialFormat = joseCompliantSerializer): KmmResult<P> =
        getPayload(serialFormat.serializersModule.serializer(), serialFormat)

    object SerialNames {
        const val PROTECTED = "protected"
        const val HEADER = "header"
        const val SIGNATURE = "signature"
        const val SIGNATURES = "signatures"
        const val PAYLOAD = "payload"

        /* Shapes */
        const val COMPACT = "compact"
        const val FLATTENED = "flattened"
        const val GENERAL = "general"

    }

    companion object {
        fun getSignature(algorithm: JwsAlgorithm, plainSignature: ByteArray): CryptoSignature.RawByteEncodable =
            when (algorithm) {
                is JwsAlgorithm.Signature.EC -> CryptoSignature.EC.fromRawBytes(algorithm.ecCurve, plainSignature)
                is JwsAlgorithm.Signature.RSA -> CryptoSignature.RSA(plainSignature)
                else -> throw SerializationException("Unsupported algorithm for JWS signature element: $algorithm")
            }

        fun getEncodedProtectedHeader(protectedHeader: ByteArray?): String =
            protectedHeader?.encodeToString(Base64UrlStrict).orEmpty()

        /**
         * Builds the RFC 7515 signing input from raw protected-header bytes and raw payload bytes.
         *
         * [payload] must be plain payload bytes; this helper base64url-encodes it internally.
         */
        fun getSignatureInput(protectedHeader: ByteArray?, payload: ByteArray) =
            "${getEncodedProtectedHeader(protectedHeader)}.${payload.encodeToString(Base64UrlStrict)}".encodeToByteArray()
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
