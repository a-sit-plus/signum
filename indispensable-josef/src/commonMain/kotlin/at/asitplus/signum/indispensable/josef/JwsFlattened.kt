package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlNoPaddingSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.serializer

/**
 * A JWS with one [payload] and one [signature], whose JOSE header can contain both protected and
 * unprotected parameters.
 *
 * This is the decoded form of Flattened JSON Serialization. The payload is decoded as [P], and the protected and
 * unprotected header parameters are combined into an [H]. [jws] retains the original [Raw] representation,
 * including the bytes used to construct the signature's signing input.
 *
 * [header] exposes the combined header; [unprotectedHeaderMembers] identifies its unprotected parameters by JSON name.
 * The signature covers the payload and protected header parameters; unprotected header parameters are unsigned.
 *
 * Deserialize received JSON as [Raw], then call [Raw.typed] to decode its payload, header, and signature.
 * [toCompact] produces a [JwsCompact] view when the original representation has a protected header and
 * no unprotected header.
 * Direct construction requires the decoded values to agree with [jws].
 *
 * Decoding does not verify the signature. To verify it, use [signature] and `jws.signatureInput`.
 */
data class JwsFlattened<out P, H : JwsHeaderBase>(
    override val jws: Raw,
    override val payload: P,
    internal val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature
) : JwsTyped<JwsFlattened.Raw, P, H>() {

    val header = wrappedHeader.header
    val unprotectedHeaderMembers = wrappedHeader.unprotectedHeaderMembers

    /**
     * Flattened JSON JWS over-the-wire format.
     *
     * The JSON object has one base64url-encoded `payload` member and one base64url-encoded `signature` member.
     * The optional `protected` member contains a base64url-encoded header fragment; the optional `header` member
     * contains an unprotected header fragment as a [JsonObject].
     *
     * Either fragment may be partial or contain unmodeled parameters. Creating a typed view requires their
     * strict union to decode as the chosen [JwsHeaderBase] implementation.
     *
     * Byte arrays contain decoded data. JSON serialization applies base64url encoding to the payload,
     * protected header, and signature; callers should not pre-encode them.
     *
     * Use [typed] to decode a [JwsFlattened] view.
     */
    @ConsistentCopyVisibility
    @Serializable
    data class Raw internal constructor(
        @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
        @SerialName(SerialNames.PROTECTED)
        val plainProtectedHeader: ByteArray? = null,
        @SerialName(SerialNames.HEADER)
        val unprotectedHeader: JsonObject? = null,
        @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
        @SerialName(SerialNames.PAYLOAD)
        override val plainPayload: ByteArray,
        @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
        @SerialName(SerialNames.SIGNATURE)
        val plainSignature: ByteArray
    ) : JwsRaw() {

        init {
            plainProtectedHeader.requireAbsentIfEmptyProtectedHeader()
        }

        @Transient
        val signatureInput = getSignatureInput(plainProtectedHeader, plainPayload)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Raw

            if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
            if (unprotectedHeader != other.unprotectedHeader) return false
            if (!plainPayload.contentEquals(other.plainPayload)) return false
            if (!plainSignature.contentEquals(other.plainSignature)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = plainProtectedHeader?.contentHashCode() ?: 0
            result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
            result = 31 * result + plainPayload.contentHashCode()
            result = 31 * result + plainSignature.contentHashCode()
            return result
        }

        companion object {
            /**
             * Creates a flattened JWS, splitting [JwsHeaderWrapped.header] according to
             * [JwsHeaderWrapped.unprotectedHeaderMembers].
             *
             * [payload] must be the plain payload bytes. Do not base64url-encode it before calling this overload;
             * flattened JSON serialization and signing input construction apply base64url encoding internally.
             */
            @Deprecated("Will be replaced by real signing service")
            suspend operator fun invoke(
                wrappedHeader: JwsHeaderWrapped<*>,
                payload: ByteArray,
                signer: suspend (ByteArray) -> ByteArray
            ): Raw {
                val plainProtectedHeader = wrappedHeader.protectedHeader
                    .takeUnless { it.toProtectedHeaderJsonObject().isEmpty() }
                val unprotectedHeader = wrappedHeader.unprotectedHeader
                    .takeUnless { it.isEmpty() }
                return Raw(
                    plainProtectedHeader,
                    unprotectedHeader,
                    payload,
                    signer(getSignatureInput(plainProtectedHeader, payload))
                )
            }
        }
    }
}

/** Decodes a [JwsFlattened] view while retaining this raw flattened representation. */
inline fun <reified P, reified H : JwsHeaderBase> JwsFlattened.Raw.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsFlattened<P, H> = typed(
    payloadSerializer = serialFormat.serializersModule.serializer<P>(),
    headerSerializer = serialFormat.serializersModule.serializer<H>(),
    serialFormat = serialFormat,
)

/** Decodes a typed view using explicit payload and header serializers, retaining the original wire object. */
fun <P, H : JwsHeaderBase> JwsFlattened.Raw.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
    serialFormat: Json = joseCompliantSerializer,
): JwsFlattened<P, H> =
    JwsHeaderWrapped.fromParts(
        serializer = headerSerializer,
        protectedHeader = plainProtectedHeader,
        unprotectedHeader = unprotectedHeader,
        serialFormat = serialFormat,
    ).let { wrapped ->
        JwsFlattened(
            this,
            getPayload(payloadSerializer, serialFormat).getOrThrow(),
            wrapped,
            JwsRaw.getSignature(wrapped.header.algorithm, plainSignature)
        )
    }

/**
 * Converts to a [JwsCompact] view, retaining the decoded payload, header, and signature.
 * The original wire representation must have a protected header and no unprotected header.
 */
fun <P, H : JwsHeaderBase> JwsFlattened<P, H>.toCompact() =
    JwsCompact(jws.toCompact(), payload, wrappedHeader, signature)

val JwsFlattened.Raw.protectedHeader: JsonObject?
    get() = plainProtectedHeader?.toProtectedHeaderJsonObject()

/**
 * Converts a raw flattened JWS to the equivalent [JwsCompact.Raw] representation.
 *
 * This requires a protected header and the absence of an unprotected header, because compact JWS can only carry
 * protected parameters.
 * Protected bytes are retained without decoding a header model.
 */
fun JwsFlattened.Raw.toCompact(): JwsCompact.Raw {
    require(unprotectedHeader == null) { "Compact Serialization does not support unprotected header" }
    requireNotNull(plainProtectedHeader)
    return JwsCompact.Raw(
        plainProtectedHeader = plainProtectedHeader,
        plainPayload = plainPayload,
        plainSignature = plainSignature,
    )
}

/**
 * Combines raw flattened JWS values with the same payload into a [JwsGeneral.Raw] representation.
 */
fun List<JwsFlattened.Raw>.toGeneral(): JwsGeneral.Raw {
    require(isNotEmpty()) { "General JWS requires at least one signature" }
    val payload = this[0].plainPayload
    val signatures = this.map {
        require(payload.contentEqualsIfArray(it.plainPayload)) {
            "Additional signed JWS payload must match existing payload"
        }
        SignatureElement(
            plainSignature = it.plainSignature,
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
        )
    }
    return JwsGeneral.Raw(
        plainPayload = payload,
        signatureElements = signatures
    )
}
