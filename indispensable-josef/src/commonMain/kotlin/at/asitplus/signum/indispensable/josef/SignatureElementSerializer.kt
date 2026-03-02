package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject


object SignatureElementSerializer : KSerializer<SignatureElement> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("SignatureElement") {
        element("protected", JwsProtectedHeaderSerializer.descriptor)
        element("signature", ByteArrayBase64UrlSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: SignatureElement) {
        val jsonEncoder = encoder as? JsonEncoder
            ?: throw SerializationException("SignatureElement can only be serialized to JSON")

        val parsedSigInput = value.plainSignatureInput.decodeToString().split(".")

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

    override fun deserialize(decoder: Decoder): SignatureElement = decoder.decodeStructure(descriptor) {
        var protectedHeader: JwsHeader? = null
        var signatureBytes: ByteArray? = null

        while (true) {
            when (val index = decodeElementIndex(descriptor)) {
                CompositeDecoder.DECODE_DONE -> break
                0 -> protectedHeader = decodeSerializableElement(descriptor, 0, JwsProtectedHeaderSerializer)
                1 -> signatureBytes = decodeSerializableElement(descriptor, 1, ByteArrayBase64UrlSerializer)
                else -> throw SerializationException("Unexpected index $index")
            }
        }

        val header = protectedHeader ?: throw SerializationException("Missing required field 'protected'")
        val rawSignature = signatureBytes ?: throw SerializationException("Missing required field 'signature'")

        val signature = when (val alg = header.algorithm) {
            is JwsAlgorithm.Signature.EC -> CryptoSignature.EC.fromRawBytes(alg.ecCurve, rawSignature)
            is JwsAlgorithm.Signature.RSA -> CryptoSignature.RSA(rawSignature)
            else -> throw SerializationException("Unsupported algorithm for JWS signature element: $alg")
        }

        SignatureElement(
            protectedHeader = header,
            signature = signature,
        )
    }
}