package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*


object SignatureElementSerializer : KSerializer<SignatureElement> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("SignatureElement") {
        element("protected", JwsProtectedHeaderSerializer.descriptor)
        element("signature", ByteArrayBase64UrlSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: SignatureElement) {
        val jsonEncoder = encoder as? JsonEncoder
            ?: throw SerializationException("SignatureElement can only be serialized to JSON")

        val parsedSigInput = value.plainHeaderInput.decodeToString().split(".")

        jsonEncoder.encodeJsonElement(
            buildJsonObject {
                put("protected", JsonPrimitive(parsedSigInput[0]))
                put(
                    "signature",
                    jsonEncoder.json.encodeToJsonElement(ByteArrayBase64UrlSerializer, value.signature.rawByteArray),
                )
            }
        )
    }

    override fun deserialize(decoder: Decoder): SignatureElement {
        val jsonDecoder = decoder as? JsonDecoder
            ?: throw SerializationException("JwsGeneral can only be deserialized from JSON")
        val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
        val rawHeader = jsonObject[SignatureElement.SerialNames.JWS_PROTECTED_HEADER]
            ?: throw SerializationException("Missing required field 'protected'")
        val rawSignature = Json.decodeFromJsonElement(
            ByteArrayBase64UrlSerializer,
            jsonObject[SignatureElement.SerialNames.JWS_SIGNATURE]
                ?: throw SerializationException("Missing required field 'signature'")
        )

        val header = Json.decodeFromJsonElement(JwsProtectedHeaderSerializer, rawHeader)

        val signature = when (val alg = header.algorithm) {
            is JwsAlgorithm.Signature.EC -> CryptoSignature.EC.fromRawBytes(alg.ecCurve, rawSignature)
            is JwsAlgorithm.Signature.RSA -> CryptoSignature.RSA(rawSignature)
            else -> throw SerializationException("Unsupported algorithm for JWS signature element: $alg")
        }

        return SignatureElement(
            protectedHeader = header,
            signature = signature,
            plainHeaderInput = (rawHeader as JsonPrimitive).content.encodeToByteArray()
        )
    }
}