package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.JWS.SerialNames
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

object JwsSerializer: KSerializer<JWS> {
    @OptIn(InternalSerializationApi::class)
    override val descriptor: SerialDescriptor = buildSerialDescriptor("JWS", PolymorphicKind.SEALED) {
        element(SerialNames.COMPACT, JwsCompactStringSerializer.descriptor)
        element(SerialNames.FLATTENED, JwsFlattened.Companion.serializer().descriptor)
        element(SerialNames.GENERAL, JwsGeneral.Companion.serializer().descriptor)
    }

    override fun serialize(
        encoder: Encoder,
        value: JWS
    ) {
        require(encoder is JsonEncoder) { "JWS serialization requires a JsonDecoder" }
        when (value) {
            is JwsCompact -> encoder.encodeSerializableValue(JwsCompactStringSerializer, value)
            is JwsFlattened -> encoder.encodeSerializableValue(JwsFlattened.Companion.serializer(), value)
            is JwsGeneral -> encoder.encodeSerializableValue(JwsGeneral.Companion.serializer(), value)
        }
    }

    override fun deserialize(decoder: Decoder): JWS {
        require(decoder is JsonDecoder) { "JWS deserialization requires a JsonDecoder" }
        val jsonElement = decoder.decodeJsonElement()

        return when (jsonElement) {
            is JsonPrimitive -> decoder.json.decodeFromJsonElement(JwsCompactStringSerializer, jsonElement)
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
                        decoder.json.decodeFromJsonElement(JwsGeneral.Companion.serializer(), jsonElement)

                    hasFlattenedSignature ->
                        decoder.json.decodeFromJsonElement(JwsFlattened.Companion.serializer(), jsonElement)

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