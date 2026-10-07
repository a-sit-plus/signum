package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json

/**
 * Typed payload, effective header with member placement, and signature over an unchanged flattened [jws].
 * Direct construction requires the decoded values to agree with the retained wire object.
 */
data class JwsFlattenedTyped<out P, H : JwsHeaderBase>(
    override val jws: JwsFlattened,
    override val payload: P,
    val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature
) : JwsTyped<JwsFlattened, P, H>()

inline fun <reified P, reified H : JwsHeaderBase> JwsFlattened.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsFlattenedTyped<P, H> =
    JwsHeaderWrapped.fromParts<H>(
        protectedHeader = plainProtectedHeader,
        unprotectedHeader = unprotectedHeader,
        serialFormat = serialFormat,
    ).let { wrapped ->
        JwsFlattenedTyped(
            this,
            getPayload<P>(serialFormat).getOrThrow(),
            wrapped,
            JWS.getSignature(wrapped.header.algorithm, plainSignature)
        )
    }

fun <P, H : JwsHeaderBase> JwsFlattenedTyped<P, H>.toJwsCompactTyped() =
    JwsCompactTyped(jws.toJwsCompact(), payload, wrappedHeader, signature)
