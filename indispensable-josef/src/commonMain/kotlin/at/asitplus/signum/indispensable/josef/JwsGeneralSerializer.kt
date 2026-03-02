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
    private val signaturesSerializer = ListSerializer(SignatureElement.serializer())

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("JwsGeneral") {
        element("payload", PrimitiveSerialDescriptor("payload", PrimitiveKind.STRING))
        element("signatures", signaturesSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: JwsGeneral<P>) {
        val jsonEncoder = encoder as? JsonEncoder
            ?: throw SerializationException("JwsGeneral can only be serialized to JSON")

        val encodedPayload = value.signatures.first().plainSignatureInput.decodeToString().split(".")[1]

        jsonEncoder.encodeJsonElement(
            buildJsonObject {
                put("payload", JsonPrimitive(encodedPayload))
                put(
                    "signatures",
                    jsonEncoder.json.encodeToJsonElement(signaturesSerializer, value.signatures),
                )
            }
        )
    }

    override fun deserialize(decoder: Decoder): JwsGeneral<P> {
        val jsonDecoder = decoder as? JsonDecoder
            ?: throw SerializationException("JwsGeneral can only be deserialized from JSON")
        val jsonObject = jsonDecoder.decodeJsonElement().jsonObject

        val encodedPayload = jsonObject["payload"]?.jsonPrimitive?.content
            ?: throw SerializationException("Missing required field 'payload'")
        val payload = jsonDecoder.json.decodeFromString(
            payloadSerializer,
            encodedPayload.decodeToByteArray(Base64UrlStrict).decodeToString(),
        )

        val signaturesElement = jsonObject["signatures"]
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
            signature.copy(plainSignatureInput = "$protectedPart.$encodedPayload".encodeToByteArray())
        }

        return JwsGeneral(
            payload = payload,
            signatures = signaturesWithInput,
        )
    }
}
