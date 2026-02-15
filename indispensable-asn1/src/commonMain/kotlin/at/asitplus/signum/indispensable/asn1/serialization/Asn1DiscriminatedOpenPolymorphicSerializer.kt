package at.asitplus.signum.indispensable.asn1.serialization

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Shared base for ASN.1 open-polymorphic serializers that dispatch by a discriminator.
 *
 * Implementations provide:
 * - [leadingTags] for ambiguity checks
 * - encode-time serializer selection from runtime value
 * - decode-time serializer selection from current ASN.1 element
 */
internal abstract class Asn1DiscriminatedOpenPolymorphicSerializer<T : Any>(
    serialName: String,
) : KSerializer<T>, Asn1LeadingTagsDescriptor {

    final override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(serialName, PrimitiveKind.STRING)
            .withDynamicAsn1LeadingTags { leadingTags }

    protected abstract fun serializerForEncode(value: T): KSerializer<out T>
    protected abstract fun serializerForDecode(decoder: DerDecoder): DeserializationStrategy<T>

    //TODO OID
    override fun serialize(encoder: Encoder, value: T) {
        val derEncoder = encoder.requireDerEncoder(descriptor.serialName)
        val selected = serializerForEncode(value)
        @Suppress("UNCHECKED_CAST")
        derEncoder.encodeSerializableValue(selected as KSerializer<Any?>, value as Any?)
    }

    final override fun deserialize(decoder: Decoder): T {
        val derDecoder = decoder.requireDerDecoder(descriptor.serialName)
        val selected = serializerForDecode(derDecoder)
        return derDecoder.decodeCurrentElementWith(selected)
    }
}
