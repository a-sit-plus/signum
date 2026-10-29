package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json

/**
 * Typed payload and header views over a retained [JwsRaw] wire object.
 *
 * Use the concrete compact, flattened, or general view to access decoded headers and signatures.
 * Create signed values through [JwsSigner].
 * Forward [raw] or use the concrete serializers from [JwsTypedSerializerTemplate] to preserve the original signed bytes.
 * Typed decoding does not verify signatures or establish key trust.
 */
sealed class JwsTyped<out J : JwsRaw, out H : JwsHeader, out P> {
    abstract val raw: J
    abstract val payload: P

    final override fun toString() = raw.toString()

    companion object {
        inline operator fun <reified H : JwsHeader, reified P> invoke(
            base64UrlString: String,
            serialFormat: Json = joseCompliantSerializer,
        ) = JwsCompact<H, P>(base64UrlString, serialFormat)

        inline operator fun <reified H : JwsHeader, reified P> invoke(
            jwsFlattened: List<JwsFlattened.Raw>,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsGeneral<H, P> = JwsGeneral<H, P>(jwsFlattened, serialFormat)

    }
}
