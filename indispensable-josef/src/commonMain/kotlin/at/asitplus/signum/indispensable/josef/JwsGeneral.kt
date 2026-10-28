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
 * Typed payload and ordered [signatureViews] over an unchanged general [jws].
 * Each pair keeps an effective header with its member placement and decoded signature together, in wire order.
 * Use [JwsGeneral.Raw.typed] to decode a general JWS.
 *
 * @constructor Kept private so construction and generated `copy()` cannot bypass the signature-list snapshot.
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
     * General JSON JWS.
     *
     * A general JWS carries one payload and one or more [SignatureElement]s. Each [SignatureElement] contains the header
     * fragments for one signature. [JwsGeneral] decodes ordered headers and signatures around the retained
     * wire object. All signatures in a [Raw] share the same payload.
     *
     * [plainPayload] stores the plain payload bytes. JSON serialization base64url-encodes those bytes for the `payload`
     * member, so callers should not pre-encode them.
     *
     * To access the contents of the parameters use [JwsGeneral]
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

            operator fun invoke(jwsFlattened: List<JwsFlattened.Raw>): Raw = jwsFlattened.toJwsGeneral()
        }
    }

    companion object {
        /** Copies [signatureViews] so later caller mutations cannot invalidate cached projections or wire alignment. */
        internal operator fun <P, H : JwsHeaderBase> invoke(
            jws: Raw,
            payload: P,
            signatureViews: List<Pair<JwsHeaderWrapped<H>, CryptoSignature>>,
        ): JwsGeneral<P, H> = JwsGeneral(jws, payload, buildList { addAll(signatureViews) })

        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            jwsFlattened: List<JwsFlattened.Raw>,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsGeneral<P, H> = jwsFlattened.toJwsGeneral().typed<P, H>(serialFormat)
    }
}

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

fun <P, H : JwsHeaderBase> JwsGeneral<P, H>.toJwsFlattenedTyped() =
    jws.toJwsFlattened().zip(signatureViews) { flattened, (wrappedHeader, signature) ->
        JwsFlattened(flattened, payload, wrappedHeader, signature)
    }

/**
 * Expands general JSON JWS representation into one flattened JWS per signature.
 */
fun JwsGeneral.Raw.toJwsFlattened(): List<JwsFlattened.Raw> =
    signatureElements.map {
        JwsFlattened.Raw(
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
            plainPayload = this.plainPayload,
            plainSignature = it.plainSignature
        )
    }
