package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

/**
 * Typed payload and ordered [signatureViews] over an unchanged general [jws].
 * Each pair keeps an effective header with its member placement and decoded signature together, in wire order.
 * Use [JwsGeneral.typed] to decode a general JWS.
 *
 * @constructor Kept private so construction and generated `copy()` cannot bypass the signature-list snapshot.
 */
@ConsistentCopyVisibility
data class JwsGeneralTyped<out P, H : JwsHeaderBase> private constructor(
    override val jws: JwsGeneral,
    override val payload: P,
    internal val signatureViews: List<Pair<JwsHeaderWrapped<H>, CryptoSignature>>,
) : JwsTyped<JwsGeneral, P, H>() {

    internal val wrappedHeaders = signatureViews.map { it.first }
    val headers = signatureViews.map { it.first.header }
    val unprotectedHeaderMembers = signatureViews.map { it.first.unprotectedMembers }
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

    companion object {
        /** Copies [signatureViews] so later caller mutations cannot invalidate cached projections or wire alignment. */
        internal operator fun <P, H : JwsHeaderBase> invoke(
            jws: JwsGeneral,
            payload: P,
            signatureViews: List<Pair<JwsHeaderWrapped<H>, CryptoSignature>>,
        ): JwsGeneralTyped<P, H> = JwsGeneralTyped(jws, payload, buildList { addAll(signatureViews) })

        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            jwsFlattened: List<JwsFlattened>,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsGeneralTyped<P, H> = jwsFlattened.toJwsGeneral().typed<P, H>(serialFormat)
    }
}

inline fun <reified P, reified H : JwsHeaderBase> JwsGeneral.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsGeneralTyped<P, H> = typed(
    payloadSerializer = serialFormat.serializersModule.serializer<P>(),
    headerSerializer = serialFormat.serializersModule.serializer<H>(),
    serialFormat = serialFormat,
)

/** Decodes a typed view using explicit payload and header serializers, retaining the original wire object. */
fun <P, H : JwsHeaderBase> JwsGeneral.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
    serialFormat: Json = joseCompliantSerializer,
): JwsGeneralTyped<P, H> {
    val payload = getPayload(payloadSerializer, serialFormat).getOrThrow()
    val signatureViews = signatureElements.map { element ->
        val wrappedHeader = JwsHeaderWrapped.fromParts(
            serializer = headerSerializer,
            protectedHeader = element.plainProtectedHeader,
            unprotectedHeader = element.unprotectedHeader,
            serialFormat = serialFormat,
        )
        wrappedHeader to JWS.getSignature(wrappedHeader.header.algorithm, element.plainSignature)
    }
    return JwsGeneralTyped(this, payload, signatureViews)
}

fun <P, H : JwsHeaderBase> JwsGeneralTyped<P, H>.toJwsFlattenedTyped() =
    jws.toJwsFlattened().zip(signatureViews) { flattened, (wrappedHeader, signature) ->
        JwsFlattenedTyped(flattened, payload, wrappedHeader, signature)
    }
