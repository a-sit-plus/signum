package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure


/**
 * Signature element as defined in [RFC 7515 Sec 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1)
 *
 * DOES NOT IMPLEMENT UNPROTECTED HEADERS!
 * Will only be implemented when use-case arises as this significantly
 * impacts JWS data class representation and verification
 * (The header in JWS is the union of protected and unprotected header elements)
 */
@Serializable(with = SignatureElementSerializer::class)
data class SignatureElement(
    /**
     * The [protectedHeader] member MUST be present ...when the JWS Protected
     * Header value is non-empty; otherwise, it MUST be absent.  These
     * Header Parameter values are integrity protected.
     *
     * Serialization: BASE64URL(UTF8(JWS Protected Header))
     */
    @SerialName("protected")
    @Serializable(with = JwsProtectedHeaderSerializer::class)
    val protectedHeader: JwsHeader,

    /**
     * The [signature] member MUST be present
     *
     * Serialization: BASE64URL(JWS Signature).
     */
    val signature: CryptoSignature.RawByteEncodable,

    /**
     * ASCII string `<BASE64URL(protected)>.<BASE64URL(payload)>` as used for signature verification.
     */
    @Transient
    val plainSignatureInput: ByteArray = byteArrayOf(),
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SignatureElement

        if (protectedHeader != other.protectedHeader) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protectedHeader.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }
}

object SignatureElementSerializer : KSerializer<SignatureElement> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("SignatureElement") {
        element("protected", JwsProtectedHeaderSerializer.descriptor)
        element("signature", ByteArrayBase64UrlSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: SignatureElement) {
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, JwsProtectedHeaderSerializer, value.protectedHeader)
            encodeSerializableElement(descriptor, 1, ByteArrayBase64UrlSerializer, value.signature.rawByteArray)
        }
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
