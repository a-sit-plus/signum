package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

/**
 * Typed payload, effective header with member placement, and signature over an unchanged flattened [jws].
 * Create signed values through [JwsSigner] or decode views through [typed].
 * Component construction and copying are internal.
 */
@ConsistentCopyVisibility
data class JwsFlattenedTyped<out P, H : JwsHeaderBase> internal constructor(
    override val jws: JwsFlattened,
    override val payload: P,
    internal val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature
) : JwsTyped<JwsFlattened, P, H>() {

    val header = wrappedHeader.header
    val unprotectedHeaderMembers = wrappedHeader.unprotectedHeaderMembers
}

inline fun <reified P, reified H : JwsHeaderBase> JwsFlattened.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsFlattenedTyped<P, H> = typed(
    payloadSerializer = serialFormat.serializersModule.serializer<P>(),
    headerSerializer = serialFormat.serializersModule.serializer<H>(),
    serialFormat = serialFormat,
)

/** Decodes a typed view using explicit payload and header serializers, retaining the original wire object. */
fun <P, H : JwsHeaderBase> JwsFlattened.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
    serialFormat: Json = joseCompliantSerializer,
): JwsFlattenedTyped<P, H> =
    JwsHeaderWrapped.fromParts(
        serializer = headerSerializer,
        protectedHeader = plainProtectedHeader,
        unprotectedHeader = unprotectedHeader,
        serialFormat = serialFormat,
    ).let { wrapped ->
        JwsFlattenedTyped(
            this,
            getPayload(payloadSerializer, serialFormat).getOrThrow(),
            wrapped,
            JWS.getSignature(wrapped.header.algorithm, plainSignature)
        )
    }

fun <P, H : JwsHeaderBase> JwsFlattenedTyped<P, H>.toJwsCompactTyped() =
    JwsCompactTyped(jws.toJwsCompact(), payload, wrappedHeader, signature)
