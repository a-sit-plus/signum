package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*

class JwsGeneralSerializer<P>(private val payloadSerializer: KSerializer<P>) : KSerializer<JwsGeneral<P>> {
    private val signaturesSerializer = ListSerializer(SignatureElementSerializer)

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("JwsGeneral") {
        element(JwsGeneral.SerialNames.PAYLOAD, PrimitiveSerialDescriptor(JwsGeneral.SerialNames.PAYLOAD, PrimitiveKind.STRING))
        element(JwsGeneral.SerialNames.JWS_SIGNATURES, signaturesSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: JwsGeneral<P>) {
        val jsonEncoder = encoder as? JsonEncoder
            ?: throw SerializationException("JwsGeneral can only be serialized to JSON")

        val encodedPayload = value.plainPayload.decodeToString()
        jsonEncoder.encodeJsonElement(
            buildJsonObject {
                put(JwsGeneral.SerialNames.PAYLOAD, JsonPrimitive(encodedPayload))
                put(
                    JwsGeneral.SerialNames.JWS_SIGNATURES,
                    jsonEncoder.json.encodeToJsonElement(signaturesSerializer, value.signatures),
                )
            }
        )
    }

    override fun deserialize(decoder: Decoder): JwsGeneral<P> {
        val jsonDecoder = decoder as? JsonDecoder
            ?: throw SerializationException("JwsGeneral can only be deserialized from JSON")
        val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
        require(jsonObject["header"] == null) { "Unprotected headers are currently not supported" }

        val encodedPayload = jsonObject[JwsGeneral.SerialNames.PAYLOAD]?.jsonPrimitive?.content
            ?: throw SerializationException("Missing required field 'payload'")
        val decodedPayload = encodedPayload.decodeToByteArray(Base64UrlStrict)
        val payload = if (payloadSerializer.descriptor.serialName == ByteArraySerializer().descriptor.serialName) {
            @Suppress("UNCHECKED_CAST")
            decodedPayload as P
        } else {
            jsonDecoder.json.decodeFromString(
                payloadSerializer,
                decodedPayload.decodeToString(),
            )
        }

        val signaturesElement = jsonObject[JwsGeneral.SerialNames.JWS_SIGNATURES]
            ?: throw SerializationException("Missing required field 'signatures'")
        val signatures = jsonDecoder.json.decodeFromJsonElement(signaturesSerializer, signaturesElement)
        val signatureObjects = signaturesElement.jsonArray

        if (signatureObjects.size != signatures.size) {
            throw SerializationException("Invalid 'signatures' field")
        }

        val signaturesWithInput = signatures.mapIndexed { index, signature ->
            val protectedPart = signatureObjects[index]
                .jsonObject["protected"]
                ?.jsonPrimitive
                ?.content
                ?: throw SerializationException("Missing required field 'protected' in signatures[$index]")
            signature.copy(plainHeaderInput = protectedPart.encodeToByteArray())
        }

        return JwsGeneral(
            payload = payload,
            signatures = signaturesWithInput,
            plainPayload = encodedPayload.encodeToByteArray()
        )
    }
}
