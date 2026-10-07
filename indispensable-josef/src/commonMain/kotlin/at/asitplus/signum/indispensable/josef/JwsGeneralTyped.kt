package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json

/**
 * Typed payload and ordered headers and signatures over an unchanged general [jws].
 * Direct construction requires the decoded values to agree with the retained wire object.
 */
data class JwsGeneralTyped<out P, H : JwsHeaderBase>(
    override val jws: JwsGeneral,
    override val payload: P,
    val wrappedHeaders: List<JwsHeaderWrapped<H>>,
    val signatures: List<CryptoSignature>
) : JwsTyped<JwsGeneral, P, H>() {
    companion object {
        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            jwsFlattened: List<JwsFlattened>,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsGeneralTyped<P, H> = jwsFlattened.toJwsGeneral().typed<P, H>(serialFormat)
    }
}

inline fun <reified P, reified H : JwsHeaderBase> JwsGeneral.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsGeneralTyped<P, H> {
    val wrappedHeaders = signatureElements.map {
        JwsHeaderWrapped.fromParts<H>(
            protectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
            serialFormat = serialFormat,
        )
    }

    return JwsGeneralTyped(
        this,
        getPayload<P>(serialFormat).getOrThrow(),
        wrappedHeaders,
        wrappedHeaders.zip(signatureElements) { wrapped, signatureElement ->
            JWS.getSignature(
                wrapped.header.algorithm,
                signatureElement.plainSignature
            )
        }
    )
}

fun <P, H : JwsHeaderBase> JwsGeneralTyped<P, H>.toJwsFlattenedTyped() =
    jws.toJwsFlattened().mapIndexed { index, flattened ->
        JwsFlattenedTyped(flattened, payload, wrappedHeaders[index], signatures[index])
    }
