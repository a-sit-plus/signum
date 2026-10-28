package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer

class JwsTypedSerializerTemplate<H : JwsHeader, P>(
    val headerSerializer: KSerializer<H>,
    val payloadSerializer: KSerializer<P>,
) {
    fun jwsCompactSerializer(): KSerializer<JwsCompact<H, P>> = TransformingSerializerTemplate(
        parent = JwsCompactRawStringSerializer,
        encodeAs = { it.raw },
        decodeAs = { it.typed(payloadSerializer, headerSerializer) },
    )

    fun jwsFlattenedSerializer(): KSerializer<JwsFlattened<H, P>> = TransformingSerializerTemplate(
        parent = JwsFlattened.Raw.serializer(),
        encodeAs = { it.raw },
        decodeAs = { it.typed(payloadSerializer, headerSerializer) },
    )

    fun jwsGeneralSerializer(): KSerializer<JwsGeneral<H, P>> = TransformingSerializerTemplate(
        parent = JwsGeneral.Raw.serializer(),
        encodeAs = { it.raw },
        decodeAs = { it.typed(payloadSerializer, headerSerializer) },
    )
}