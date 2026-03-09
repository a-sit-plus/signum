package at.asitplus.signum.indispensable.josef

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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement


/**
 * Wrapper for all JWS formats.
 */
@Serializable(with = JWS.JwsSerializer::class)
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
    inline fun <reified P> getPayload(serialFormat: SerialFormat = joseCompliantSerializer): P =
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

    object JwsSerializer: KSerializer<JWS> {
        @OptIn(InternalSerializationApi::class)
        override val descriptor: SerialDescriptor = buildSerialDescriptor("JWS", PolymorphicKind.SEALED) {
            element("compact", JwsCompact.serializer().descriptor)
            element("flattened", JwsFlattened.serializer().descriptor)
            element("general", JwsGeneral.serializer().descriptor)
        }

        override fun serialize(
            encoder: Encoder,
            value: JWS
        ) {
            when (value) {
                is JwsCompact -> encoder.encodeSerializableValue(JwsCompact.serializer(), value)
                is JwsFlattened -> encoder.encodeSerializableValue(JwsFlattened.serializer(), value)
                is JwsGeneral -> encoder.encodeSerializableValue(JwsGeneral.serializer(), value)
            }
        }

        override fun deserialize(decoder: Decoder): JWS {
            require(decoder is JsonDecoder) { "JWS deserialization requires a JsonDecoder" }
            val jsonElement = decoder.decodeJsonElement()

            return when (jsonElement) {
                is JsonPrimitive -> decoder.json.decodeFromJsonElement(JwsCompact.serializer(), jsonElement)
                is JsonObject -> {
                    val hasGeneralSignatures = SerialNames.SIGNATURES in jsonElement
                    val hasFlattenedSignature = SerialNames.SIGNATURE in jsonElement

                    when {
                        hasGeneralSignatures && hasFlattenedSignature ->
                            throw SerializationException(
                                "Invalid JWS JSON serialization: object must not contain both " +
                                    "'${SerialNames.SIGNATURE}' and '${SerialNames.SIGNATURES}'"
                            )

                        hasGeneralSignatures ->
                            decoder.json.decodeFromJsonElement(JwsGeneral.serializer(), jsonElement)

                        hasFlattenedSignature ->
                            decoder.json.decodeFromJsonElement(JwsFlattened.serializer(), jsonElement)

                        else ->
                            throw SerializationException(
                                "Invalid JWS JSON serialization: object must contain " +
                                    "'${SerialNames.SIGNATURE}' or '${SerialNames.SIGNATURES}'"
                            )
                    }
                }

                else -> throw SerializationException(
                    "Invalid JWS JSON serialization: expected a compact string or JSON object"
                )
            }
        }
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