package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer

/**
 * Serializes only the retained [JwsTyped.raw] wire object.
 * Decoding reconstructs the concrete typed view with the supplied payload and header serializers,
 * using the JOSE-compliant JSON format. Decoded signatures retain wire order.
 */
@Suppress("UNCHECKED_CAST")
class JwsTypedSerializerTemplate<J : JwsRaw, H : JwsHeader, P>(
    jwsSerializer: KSerializer<J>,
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
) : TransformingSerializerTemplate<JwsTyped<J, H, P>, J>(
    parent = jwsSerializer,
    encodeAs = { it.raw },
    decodeAs = { jws ->
        when (jws) {
            is JwsCompact.Raw -> jws.typed(payloadSerializer, headerSerializer)
            is JwsFlattened.Raw -> jws.typed(payloadSerializer, headerSerializer)
            is JwsGeneral.Raw -> jws.typed(payloadSerializer, headerSerializer)
        } as JwsTyped<J, H, P>
    }
)
