package at.asitplus.signum.indispensable.josef

import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.CryptoSignature
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
import kotlinx.serialization.serializer

/**
 * A JWS with one [payload], one [signature], and an entirely protected JOSE [header].
 *
 * This is the decoded form of Compact Serialization: three base64url-encoded segments joined by dots.
 * The payload is decoded as [P], and the protected header as [H]. [raw] retains the original [Raw]
 * representation, including the bytes used to construct the signature's signing input.
 *
 * Compact serialization cannot carry unprotected header parameters; [unprotectedHeaderMembers] is empty
 * when decoding a compact JWS.
 *
 * Parse a received string with `JwsCompact<H, P>(compactString)`, or decode an existing [Raw] with [Raw.typed].
 * [toString] produces the compact string; [toFlattened] produces a [JwsFlattened] view with the same signed bytes.
 * Create signed values through [JwsSigner]. Component construction and copying are internal.
 *
 * Decoding does not verify the signature. To verify it, use [signature] and `jws.signatureInput`.
 */
@ConsistentCopyVisibility
data class JwsCompact<out H : JwsHeader, out P> internal constructor(
    override val raw: Raw,
    override val payload: P,
    internal val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature
) : JwsTyped<JwsCompact.Raw, H, P>() {

    val header = wrappedHeader.header
    val unprotectedHeaderMembers = wrappedHeader.unprotectedHeaderMembers
    val signatureInput = raw.signatureInput

    /**
     * Compact JWS over-the-wire format: three base64url-encoded segments joined by dots.
     *
     * `BASE64URL(protected header).BASE64URL(payload).BASE64URL(signature)`
     *
     * The header is always protected; compact serialization has no unprotected header field.
     * Byte arrays contain decoded data. Serialization applies base64url encoding to the protected header,
     * payload, and signature; callers should not pre-encode them.
     *
     * Parse a string with `JwsCompact.Raw(compactString)` to decode the segments without interpreting the header
     * or payload. Use [typed] to decode a [JwsCompact] view.
     *
     * Use [toString] for the compact string, and [JwsCompactRawStringSerializer] when embedding it in JSON.
     *
     * See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515).
     */
    @ConsistentCopyVisibility
    data class Raw internal constructor(
        val plainProtectedHeader: ByteArray,
        override val plainPayload: ByteArray,
        val plainSignature: ByteArray,
    ) : JwsRaw() {

        @Transient
        val signatureInput = getSignatureInput(plainProtectedHeader, plainPayload)

        override fun toString() = "${signatureInput.decodeToString()}.${plainSignature.encodeToString(Base64UrlStrict)}"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Raw

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
             * Parses compact serialization into a [Raw] value without decoding its payload or header.
             */
            @Throws(SerializationException::class)
            operator fun invoke(
                base64UrlString: String,
            ): Raw = catchingUnwrappedAs(::SerializationException) {
                require(!base64UrlString.contains("=")) { "Trailing = are not supported. See RFC 7515" }
                val parts = base64UrlString.split('.')

                if (parts.size != 3) {
                    throw SerializationException(
                        "Invalid JWS compact serialization: expected 3 parts, got ${parts.size}"
                    )
                }

                Raw(
                    plainProtectedHeader = parts[0].decodeToByteArray(Base64UrlStrict),
                    plainPayload = parts[1].decodeToByteArray(Base64UrlStrict),
                    plainSignature = parts[2].decodeToByteArray(Base64UrlStrict),
                )
            }.getOrThrow()
        }
    }

    companion object {
        /** Parses compact serialization and decodes its typed payload, header, and signature. */
        inline operator fun <reified H : JwsHeader, reified P> invoke(
            base64UrlString: String,
            serialFormat: Json = joseCompliantSerializer,
        ) = Raw(base64UrlString).typed<H, P>(serialFormat)
    }
}

/** Decodes a [JwsCompact] view while retaining this raw compact representation. */
inline fun <reified H : JwsHeader, reified P> JwsCompact.Raw.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsCompact<H, P> = typed(
    payloadSerializer = serialFormat.serializersModule.serializer<P>(),
    headerSerializer = serialFormat.serializersModule.serializer<H>(),
    serialFormat = serialFormat,
)

/** Decodes a typed view using explicit payload and header serializers, retaining the original wire object. */
fun <H : JwsHeader, P> JwsCompact.Raw.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
    serialFormat: Json = joseCompliantSerializer,
): JwsCompact<H, P> =
    JwsHeaderWrapped.fromParts(
        serializer = headerSerializer,
        protectedHeader = plainProtectedHeader,
        serialFormat = serialFormat,
    ).let { wrapped ->
        JwsCompact(
            this,
            getPayload(payloadSerializer, serialFormat).getOrThrow(),
            wrapped,
            JwsRaw.getSignature(wrapped.header.algorithm, plainSignature)
        )
    }

/** Converts to a [JwsFlattened] view, retaining the decoded payload, header, and signature. */
fun <H : JwsHeader, P> JwsCompact<H, P>.toFlattened() =
    JwsFlattened(raw.toFlattened(), payload, wrappedHeader, signature)

/**
 * Serializes a [JwsCompact.Raw] as its compact JWS string form inside JSON.
 *
 * This serializer must be opted into explicitly to avoid accidentally treating [JwsCompact.Raw] as a JSON object.
 */
object JwsCompactRawStringSerializer : KSerializer<JwsCompact.Raw> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("JwsCompact", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsCompact.Raw) = encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): JwsCompact.Raw = JwsCompact.Raw(decoder.decodeString())
}

/**
 * Converts a raw compact JWS to the equivalent [JwsFlattened.Raw] representation.
 *
 * The protected header bytes are preserved and the unprotected header is absent, because compact serialization does
 * not support unprotected header parameters.
 */
fun JwsCompact.Raw.toFlattened(): JwsFlattened.Raw = JwsFlattened.Raw(
    plainProtectedHeader = plainProtectedHeader,
    unprotectedHeader = null,
    plainPayload = plainPayload,
    plainSignature = plainSignature,
)
