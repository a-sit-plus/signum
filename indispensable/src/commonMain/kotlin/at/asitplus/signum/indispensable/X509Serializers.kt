package at.asitplus.signum.indispensable

import kotlinx.serialization.KSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModuleBuilder
import kotlin.reflect.KClass

/** Register a contextual Signum serializer that delegates encoding to an awesn1 model. */
fun <T : WithSourceRepresentation, Model : Any> SerializersModuleBuilder.contextualAsn1(
    type: KClass<T>,
    modelSerializer: KSerializer<Model>,
    toModel: (T) -> Model,
    fromModel: (Model) -> T,
) {
    contextual(type, X509Serializer(modelSerializer, toModel, fromModel))
}

private class X509Serializer<T, Model>(
    private val delegate: KSerializer<Model>,
    private val toModel: (T) -> Model,
    private val fromModel: (Model) -> T,
) : KSerializer<T> {
    override val descriptor = delegate.descriptor
    override fun serialize(encoder: Encoder, value: T) = encoder.encodeSerializableValue(delegate, toModel(value))
    override fun deserialize(decoder: Decoder): T = fromModel(decoder.decodeSerializableValue(delegate))
}
