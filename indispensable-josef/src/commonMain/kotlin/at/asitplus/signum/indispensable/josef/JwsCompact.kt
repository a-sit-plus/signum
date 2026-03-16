package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
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
 * [JwsCompact] is intentionally *not* annotated with `@Serializable`: its JSON representation is only the compact
 * JWS string, not a JSON object. Use [JwsCompactStringSerializer] explicitly when you want that string form inside
 * a JSON document.
 *
 * For a standalone compact JWS string, use [toString] and [JwsCompact.invoke].
 */
data class JwsCompact(
    val plainProtectedHeader: ByteArray,
    override val payload: ByteArray,
    val plainSignature: ByteArray,
) : JWS() {

    @Transient
    val jwsHeader = JwsHeader.fromParts(plainProtectedHeader, null)

    @Transient
    val signature = getSignature(jwsHeader.algorithm, plainSignature)

    @Transient
    val signatureInput = getSignatureInput(plainProtectedHeader, payload)

    override fun toString() =
        "${signatureInput.decodeToString()}.${plainSignature.encodeToString(Base64UrlStrict)}"

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

    companion object {
        operator fun invoke(
            base64UrlString: String,
        ): JwsCompact {
            require(!base64UrlString.contains("=")) { "Trailing = are not supported. See RFC 7515" }
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

/**
 * Serializes a [JwsCompact] as its compact JWS string form inside JSON.
 *
 * This serializer must be opted into explicitly to avoid accidentally treating [JwsCompact] as a JSON object.
 */
object JwsCompactStringSerializer : KSerializer<JwsCompact> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsCompact", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsCompact) =
        encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): JwsCompact =
        JwsCompact(decoder.decodeString())
}

/**
 * Converts compact serialization to the equivalent flattened JSON form.
 *
 * The protected header bytes are preserved and the unprotected header is absent, because compact serialization does
 * not support unprotected header parameters.
 */
fun JwsCompact.toJwsFlattened(): JwsFlattened = JwsFlattened(
    plainProtectedHeader = plainProtectedHeader,
    unprotectedHeader = null,
    payload = payload,
    plainSignature = plainSignature,
)
