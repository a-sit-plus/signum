package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


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
    private val protectedHeader: JwsHeader =
        joseCompliantSerializer.decodeFromString(plainProtectedHeader.encodeToString(Base64UrlStrict))

    /**
     * Lenient Signature Parsing
     */
    @Transient
    val signature: CryptoSignature.RawByteEncodable
        get() = when (val alg = protectedHeader.algorithm) {
            is JwsAlgorithm.Signature.EC -> CryptoSignature.EC.fromRawBytes(alg.ecCurve, plainSignature)
            is JwsAlgorithm.Signature.RSA -> CryptoSignature.RSA(plainSignature)
            else -> throw SerializationException("Unsupported algorithm for JWS signature element: $alg")
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

        override fun serialize(encoder: Encoder, value: JwsCompact) {
            val compact = buildString {
                append(value.plainProtectedHeader.encodeToString(Base64UrlStrict))
                append('.')
                append(value.payload.encodeToString(Base64UrlStrict))
                append('.')
                append(value.plainSignature.encodeToString(Base64UrlStrict))
            }

            encoder.encodeString(compact)
        }

        override fun deserialize(decoder: Decoder): JwsCompact {
            val compact = decoder.decodeString()
            val parts = compact.split('.')

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
            } catch (e: IllegalArgumentException) {
                throw SerializationException("Invalid base64url content in JWS compact serialization", e)
            }
        }
    }
}

fun JwsCompact.toJwsFlattened(): JwsFlattened = JwsFlattened(
    plainProtectedHeader = plainProtectedHeader,
    unprotectedHeader = null,
    payload = payload,
    plainSignature = plainSignature,
)