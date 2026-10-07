package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json

data class JwsCompactTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsCompact,
    override val payload: P,
    val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature
) : JwsTyped<JwsCompact, P, H>() {
    companion object {
        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            base64UrlString: String,
            serialFormat: Json = joseCompliantSerializer,
        ) = JwsCompact(base64UrlString).typed<P, H>(serialFormat)
    }
}

inline fun <reified P, reified H : JwsHeaderBase> JwsCompact.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsCompactTyped<P, H> =
    JwsHeaderWrapped.fromParts<H>(
        protectedHeader = plainProtectedHeader,
        serialFormat = serialFormat,
    ).let { wrapped ->
        JwsCompactTyped(
            this,
            getPayload<P>(serialFormat).getOrThrow(),
            wrapped,
            JWS.getSignature(wrapped.header.algorithm, plainSignature)
        )
    }

fun <P, H : JwsHeaderBase> JwsCompactTyped<P, H>.toJwsFlattenedTyped() =
    JwsFlattenedTyped(jws.toJwsFlattened(), payload, wrappedHeader, signature)
