package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.StringFormat
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Implements compact serialization as defined in [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
 *
 * Serialized output is of the form
 * BASE64URL(UTF8(HEADER)).BASE64URL(PAYLOAD).BASE64URL(SIGNATURE)
 *
 * This class does not support an unprotected header field!
 *
 * When [JwsCompact] is serialized through a JSON format, the compact representation becomes a JSON string literal.
 * That is correct for nested usage inside a larger JSON document, but the surrounding JSON text contains quotes.
 *
 * For a standalone compact JWS string, use [toString] and [JwsCompact.invoke]
 */
@Serializable(with = JwsCompact.JwsCompactSerializer::class)
data class JwsCompact(
    @Serializable(ByteArrayBase64UrlSerializer::class)
    val plainProtectedHeader: ByteArray,
    @Serializable(ByteArrayBase64UrlSerializer::class)
    override val payload: ByteArray,
    @Serializable(ByteArrayBase64UrlSerializer::class)
    val plainSignature: ByteArray,
) : JWS() {

    @Transient
    val jwsHeader = JwsHeader.fromParts(plainProtectedHeader, null)

    val signature by lazy { getSignature(jwsHeader.algorithm, plainSignature) }
    val signatureInput by lazy { getSignatureInput(plainProtectedHeader, payload) }

    override fun toString(): String {
        val signingInput =
            getSignatureInput(plainProtectedHeader, payload).decodeToString()
        val signature =
            plainSignature.encodeToString(Base64UrlStrict)
        return "$signingInput.$signature"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsCompact

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!plainSignature.contentEquals(other.plainSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }

    object JwsCompactSerializer : KSerializer<JwsCompact> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("JwsCompact", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: JwsCompact) =
            encoder.encodeString(value.toString())

        override fun deserialize(decoder: Decoder): JwsCompact =
            JwsCompact(decoder.decodeString())
    }

    companion object {
        operator fun invoke(
            base64UrlString: String,
        ): JwsCompact {
            val parts = base64UrlString.split('.')

            if (parts.size != 3) {
                throw SerializationException(
                    "Invalid JWS compact serialization: expected 3 parts, got ${parts.size}"
                )
            }

            return try {
                JwsCompact(
                    plainProtectedHeader = parts[0].decodeToByteArray(Base64UrlStrict),
                    payload = parts[1].decodeToByteArray(Base64UrlStrict),
                    plainSignature = parts[2].decodeToByteArray(Base64UrlStrict),
                )
            } catch (e: Exception) {
                throw SerializationException("Invalid base64url content in JWS compact serialization", e)
            }
        }

        operator fun invoke(
            protectedHeader: JwsHeader,
            payload: ByteArray,
            signer: (JwsAlgorithm, ByteArray) -> ByteArray
        ): JwsCompact {
            val plainProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(protectedHeader.toPart())
            return JwsCompact(
                plainProtectedHeader = plainProtectedHeader,
                payload = payload,
                plainSignature = signer(protectedHeader.algorithm, getSignatureInput(plainProtectedHeader, payload)),
            )
        }
    }
}

fun JwsCompact.toJwsFlattened(): JwsFlattened = JwsFlattened(
    plainProtectedHeader = plainProtectedHeader,
    unprotectedHeader = null,
    payload = payload,
    plainSignature = plainSignature,
)
