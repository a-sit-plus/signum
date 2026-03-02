package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
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

        val encodedPayload = value.plainPayload.encodeToString(Base64UrlStrict)
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

        val encodedPayload = jsonObject[JwsGeneral.SerialNames.PAYLOAD]?.jsonPrimitive?.content
            ?: throw SerializationException("Missing required field 'payload'")
        val payload = jsonDecoder.json.decodeFromString(
            payloadSerializer,
            encodedPayload.decodeToByteArray(Base64UrlStrict).decodeToString(),
        )

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
