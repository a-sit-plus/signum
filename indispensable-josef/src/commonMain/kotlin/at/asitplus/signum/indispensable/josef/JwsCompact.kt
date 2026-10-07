package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
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
import kotlinx.serialization.json.Json

/**
 * Implements compact serialization as defined in [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
 *
 * Serialized output is of the form
 * BASE64URL(UTF8(HEADER)).BASE64URL(PAYLOAD).BASE64URL(SIGNATURE)
 *
 * This class does not support an unprotected header field!
 *
 * [JwsCompact] is intentionally not annotated with `@Serializable`: use [toString] for its standalone compact
 * representation, and [JwsCompactStringSerializer] when embedding that string in JSON.
 *
 * Header bytes remain opaque until decoded through [JwsCompactTyped].
 */
@ConsistentCopyVisibility
data class JwsCompact internal constructor(
    val plainProtectedHeader: ByteArray,
    override val plainPayload: ByteArray,
    val plainSignature: ByteArray,
) : JWS() {

    @Transient
    val signatureInput = getSignatureInput(plainProtectedHeader, plainPayload)

    override fun toString() = "${signatureInput.decodeToString()}.${plainSignature.encodeToString(Base64UrlStrict)}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsCompact

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (!plainPayload.contentEquals(other.plainPayload)) return false
        if (!plainSignature.contentEquals(other.plainSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader.contentHashCode()
        result = 31 * result + plainPayload.contentHashCode()
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }

    companion object {

        /**
         * Build a [at.asitplus.signum.indispensable.josef.JwsCompact] received as string
         * and immediately decode its payload and wrapped header
         */
        inline fun <reified P, reified H : JwsHeaderBase> parse(
            base64UrlString: String,
            serialFormat: Json = joseCompliantSerializer,
        ): KmmResult<Triple<JwsCompact, P, JwsHeaderWrapped<H>>> =
            catching {
                val jws = JwsCompact(base64UrlString)
                val payload = jws.getPayload<P>(serialFormat).getOrThrow()
                val header = JwsHeaderWrapped.fromParts<H>(
                    protectedHeader = jws.plainProtectedHeader,
                    serialFormat = serialFormat,
                )
                Triple(jws, payload, header)
            }

        /**
         * Build a [at.asitplus.signum.indispensable.josef.JwsCompact] received as string
         */
        @Throws(SerializationException::class)
        operator fun invoke(
            base64UrlString: String,
        ): JwsCompact = catchingUnwrappedAs(::SerializationException) {
            require(!base64UrlString.contains("=")) { "Trailing = are not supported. See RFC 7515" }
            val parts = base64UrlString.split('.')

            if (parts.size != 3) {
                throw SerializationException(
                    "Invalid JWS compact serialization: expected 3 parts, got ${parts.size}"
                )
            }

            JwsCompact(
                plainProtectedHeader = parts[0].decodeToByteArray(Base64UrlStrict),
                plainPayload = parts[1].decodeToByteArray(Base64UrlStrict),
                plainSignature = parts[2].decodeToByteArray(Base64UrlStrict),
            )
        }.getOrThrow()

        /**
         * Build a new [at.asitplus.signum.indispensable.josef.JwsCompact]
         * from components and immediately sign the correct representation.
         *
         * [payload] must be the plain payload bytes. Do not base64url-encode it before calling this overload;
         * compact serialization and signing input construction apply base64url encoding internally.
         */
        @Deprecated("Will be replaced by real signing service")
        suspend operator fun invoke(
            protectedHeader: JwsHeader,
            payload: ByteArray,
            signer: suspend (ByteArray) -> ByteArray
        ): JwsCompact = invoke(JwsHeaderWrapped(protectedHeader), payload, signer)

        /**
         * Builds a compact JWS using a wrapped custom header. Compact serialization cannot carry unprotected
         * members, so every represented header member must be protected.
         */
        @Deprecated("Will be replaced by real signing service")
        suspend operator fun invoke(
            wrappedHeader: JwsHeaderWrapped<*>,
            payload: ByteArray,
            signer: suspend (ByteArray) -> ByteArray,
        ): JwsCompact {
            require(wrappedHeader.effectiveUnprotectedMembers.isEmpty()) {
                "Compact Serialization does not support unprotected header members"
            }
            val plainProtectedHeader = wrappedHeader.toProtectedHeader()
            return JwsCompact(
                plainProtectedHeader = plainProtectedHeader,
                plainPayload = payload,
                plainSignature = signer(getSignatureInput(plainProtectedHeader, payload)),
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
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("JwsCompact", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsCompact) = encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): JwsCompact = JwsCompact(decoder.decodeString())
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
    plainPayload = plainPayload,
    plainSignature = plainSignature,
)
