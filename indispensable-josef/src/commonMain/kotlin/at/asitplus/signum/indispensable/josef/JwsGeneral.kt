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
import kotlinx.serialization.serializer

/**
 * A JWS with one shared [payload] and one or more signatures, each with its own JOSE header.
 *
 * This is the decoded form of General JSON Serialization. The payload is decoded as [P], and each signature's
 * protected and unprotected header parameters are combined into an [H]. [jws] retains the original [Raw]
 * representation, including the bytes used to construct each signature's signing input.
 *
 * Entries at the same index in [headers], [unprotectedHeaderMembers], and [signatures] describe the same signature,
 * in the order of [Raw.signatureElements]. [toFlattened] produces one [JwsFlattened] view per signature.
 *
 * Decode a received [Raw] with [Raw.typed], or combine raw flattened JWS values with
 * `JwsGeneral<P, H>(flattenedValues)`. Combining values requires identical payload bytes.
 *
 * Decoding does not verify signatures. To verify signature `i`, use `signatures[i]` and `jws.signatureInputs[i]`.
 */
@ConsistentCopyVisibility
data class JwsGeneral<out P, H : JwsHeaderBase> private constructor(
    override val jws: Raw,
    override val payload: P,
    internal val signatureViews: List<Pair<JwsHeaderWrapped<H>, CryptoSignature>>,
) : JwsTyped<JwsGeneral.Raw, P, H>() {

    internal val wrappedHeaders = signatureViews.map { it.first }
    val headers = signatureViews.map { it.first.header }
    val unprotectedHeaderMembers = signatureViews.map { it.first.unprotectedHeaderMembers }
    val signatures = signatureViews.map { it.second }

    init {
        require(signatureViews.size == jws.signatureElements.size) {
            "Signature views must match the number of wire signature elements"
        }
        require(signatureViews.indices.all { index ->
            signatureViews[index].second.joseBytes.contentEquals(jws.signatureElements[index].plainSignature)
        }) {
            "Signature views must match the wire signature bytes in order"
        }
    }

    /**
     * General JSON JWS over-the-wire format.
     *
     * The JSON object has one base64url-encoded `payload` member and a non-empty `signatures` array.
     * Each [SignatureElement] contains a signature and its optional protected and unprotected header fragments.
     * Every signature uses the same [plainPayload] bytes.
     *
     * Byte arrays contain decoded data. JSON serialization applies base64url encoding to the payload,
     * protected headers, and signatures; callers should not pre-encode them.
     *
     * Use [typed] to decode a [JwsGeneral] view.
     *
     * @constructor Kept private so construction and generated `copy()` cannot bypass the signature-list snapshot.
     */
    @ConsistentCopyVisibility
    @Serializable
    data class Raw private constructor(
        @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
        @SerialName(SerialNames.PAYLOAD)
        override val plainPayload: ByteArray,
        @Serializable
        @SerialName(SerialNames.SIGNATURES)
        val signatureElements: List<SignatureElement>
    ) : JwsRaw() {

        init {
            require(signatureElements.isNotEmpty()) { "At least one signature is required" }
        }

        @Transient
        val signatureInputs = signatureElements.map { getSignatureInput(it.plainProtectedHeader, plainPayload) }

        /**
         * Returns a new [Raw] with one additional signature over the same payload.
         */
        fun appendSignature(jwsFlattened: JwsFlattened.Raw): Raw {
            require(plainPayload.contentEqualsIfArray(jwsFlattened.plainPayload)) {
                "Additional signed JWS payload must match existing payload"
            }

            return copy(
                signatureElements = signatureElements + SignatureElement(
                    plainSignature = jwsFlattened.plainSignature,
                    unprotectedHeader = jwsFlattened.unprotectedHeader,
                    plainProtectedHeader = jwsFlattened.plainProtectedHeader,
                )
            )
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Raw

            if (!plainPayload.contentEquals(other.plainPayload)) return false
            if (signatureElements != other.signatureElements) return false

            return true
        }

        override fun hashCode(): Int {
            var result = plainPayload.contentHashCode()
            result = 31 * result + signatureElements.hashCode()
            return result
        }

        companion object {
            /** Copies [signatureElements] so later caller mutations cannot invalidate cached signing inputs. */
            internal operator fun invoke(
                plainPayload: ByteArray,
                signatureElements: List<SignatureElement>,
            ): Raw = Raw(plainPayload, buildList { addAll(signatureElements) })

            /** Combines raw flattened signatures over one payload into a [Raw] representation. */
            operator fun invoke(jwsFlattened: List<JwsFlattened.Raw>): Raw = jwsFlattened.toGeneral()
        }
    }

    companion object {
        /** Copies [signatureViews] so later caller mutations cannot invalidate cached projections or wire alignment. */
        internal operator fun <P, H : JwsHeaderBase> invoke(
            jws: Raw,
            payload: P,
            signatureViews: List<Pair<JwsHeaderWrapped<H>, CryptoSignature>>,
        ): JwsGeneral<P, H> = JwsGeneral(jws, payload, buildList { addAll(signatureViews) })

        /** Combines raw flattened signatures over one payload and decodes a typed general view. */
        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            jwsFlattened: List<JwsFlattened.Raw>,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsGeneral<P, H> = jwsFlattened.toGeneral().typed<P, H>(serialFormat)
    }
}

/** Decodes a [JwsGeneral] view while retaining this raw general representation and its signature order. */
inline fun <reified P, reified H : JwsHeaderBase> JwsGeneral.Raw.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsGeneral<P, H> = typed(
    payloadSerializer = serialFormat.serializersModule.serializer<P>(),
    headerSerializer = serialFormat.serializersModule.serializer<H>(),
    serialFormat = serialFormat,
)

/** Decodes a typed view using explicit payload and header serializers, retaining the original wire object. */
fun <P, H : JwsHeaderBase> JwsGeneral.Raw.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
    serialFormat: Json = joseCompliantSerializer,
): JwsGeneral<P, H> {
    val payload = getPayload(payloadSerializer, serialFormat).getOrThrow()
    val signatureViews = signatureElements.map { element ->
        val wrappedHeader = JwsHeaderWrapped.fromParts(
            serializer = headerSerializer,
            protectedHeader = element.plainProtectedHeader,
            unprotectedHeader = element.unprotectedHeader,
            serialFormat = serialFormat,
        )
        wrappedHeader to JwsRaw.getSignature(wrappedHeader.header.algorithm, element.plainSignature)
    }
    return JwsGeneral(this, payload, signatureViews)
}

/** Expands into [JwsFlattened] views in signature order, retaining the decoded payload and headers. */
fun <P, H : JwsHeaderBase> JwsGeneral<P, H>.toFlattened() =
    jws.toFlattened().zip(signatureViews) { flattened, (wrappedHeader, signature) ->
        JwsFlattened(flattened, payload, wrappedHeader, signature)
    }

/**
 * Expands a raw general JWS into one [JwsFlattened.Raw] per signature, retaining wire order and signed bytes.
 */
fun JwsGeneral.Raw.toFlattened(): List<JwsFlattened.Raw> =
    signatureElements.map {
        JwsFlattened.Raw(
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
            plainPayload = this.plainPayload,
            plainSignature = it.plainSignature
        )
    }
