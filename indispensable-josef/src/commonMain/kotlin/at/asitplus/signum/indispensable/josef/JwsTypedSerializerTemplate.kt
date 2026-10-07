package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer

/**
 * Convenience Serializer Template to serialize through wrapper and
 * only serialize [JwsTyped.jws].
 */
@Suppress("UNCHECKED_CAST")
class JwsTypedSerializerTemplate<J : JWS, P, H : JwsHeaderBase>(
    jwsSerializer: KSerializer<J>,
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
) : TransformingSerializerTemplate<JwsTyped<J, P, H>, J>(
    parent = jwsSerializer,
    encodeAs = { it.jws },
    decodeAs = { jws ->
        when (jws) {
            is JwsCompact ->
                JwsHeaderWrapped.fromParts(headerSerializer, jws.plainProtectedHeader, null).let { wrapped ->
                    JwsCompactTyped(
                        jws,
                        jws.getPayload(payloadSerializer).getOrThrow(),
                        wrapped,
                        JWS.getSignature(wrapped.header.algorithm, jws.plainSignature),
                    )
                }

            is JwsFlattened ->
                JwsHeaderWrapped.fromParts(
                    headerSerializer,
                    jws.plainProtectedHeader,
                    jws.unprotectedHeader,
                ).let { wrapped ->
                    JwsFlattenedTyped(
                        jws,
                        jws.getPayload(payloadSerializer).getOrThrow(),
                        wrapped,
                        JWS.getSignature(wrapped.header.algorithm, jws.plainSignature),
                    )
                }

            is JwsGeneral -> jws.signatureElements.map {
                JwsHeaderWrapped.fromParts(
                    headerSerializer,
                    it.plainProtectedHeader,
                    it.unprotectedHeader,
                )
            }.let { wrappedHeaders ->
                JwsGeneralTyped(
                    jws,
                    jws.getPayload(payloadSerializer).getOrThrow(),
                    wrappedHeaders,
                    wrappedHeaders.zip(jws.signatureElements) { wrapped, signatureElement ->
                        JWS.getSignature(
                            wrapped.header.algorithm,
                            signatureElement.plainSignature,
                        )
                    },
                )
            }
        } as JwsTyped<J, P, H>
    }
)
