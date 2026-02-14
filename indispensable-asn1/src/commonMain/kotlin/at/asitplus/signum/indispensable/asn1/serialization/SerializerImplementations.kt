@file:OptIn(
    kotlinx.serialization.SealedSerializationApi::class,
)

package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.encoding.parse
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Descriptor contract for declaring leading ASN.1 tags for ambiguity analysis.
 *
 * Implement this on custom [SerialDescriptor] implementations when serializer logic
 * cannot be inferred from descriptor kind alone.
 *
 * Use an empty set when leading tags are unknown/value-dependent.
 */
interface Asn1LeadingTagsDescriptor {
    val leadingTags: Set<Asn1Element.Tag>
}

private class Asn1LeadingTagsAnnotation(
    private val provider: () -> Set<Asn1Element.Tag>
) : Annotation {
    val leadingTags: Set<Asn1Element.Tag>
        get() = provider()
}

private val asn1OpaqueDelegateDescriptor: SerialDescriptor =
    SerialDescriptor("Asn1DerSerializer", ByteArraySerializer().descriptor)

private open class Asn1LeadingTagsSerialDescriptor(
    private val delegate: SerialDescriptor,
    private val leadingTagsProvider: () -> Set<Asn1Element.Tag>,
) : SerialDescriptor by delegate, Asn1LeadingTagsDescriptor {
    override val leadingTags: Set<Asn1Element.Tag>
        get() = leadingTagsProvider()

    override val annotations: List<Annotation>
        get() = delegate.annotations + Asn1LeadingTagsAnnotation(leadingTagsProvider)
}

private class Asn1OpaqueSerializerDescriptor(
    leadingTagsProvider: () -> Set<Asn1Element.Tag>,
) : Asn1LeadingTagsSerialDescriptor(asn1OpaqueDelegateDescriptor, leadingTagsProvider)

/**
 * Returns a descriptor that carries ASN.1 leading-tag metadata for ambiguity checks.
 */
fun SerialDescriptor.withAsn1LeadingTags(leadingTags: Set<Asn1Element.Tag>): SerialDescriptor =
    Asn1LeadingTagsSerialDescriptor(this) { leadingTags }

internal fun SerialDescriptor.withDynamicAsn1LeadingTags(
    leadingTagsProvider: () -> Set<Asn1Element.Tag>,
): SerialDescriptor = Asn1LeadingTagsSerialDescriptor(this, leadingTagsProvider)

internal val SerialDescriptor.asn1LeadingTagsOrNull: Set<Asn1Element.Tag>?
    get() = (this as? Asn1LeadingTagsDescriptor)?.leadingTags
        ?: annotations.lastOrNull { it is Asn1LeadingTagsAnnotation }
            ?.let { it as Asn1LeadingTagsAnnotation }
            ?.leadingTags

internal object Asn1ElementSerializer : KSerializer<Asn1Element> {
    private val delegate = ByteArraySerializer()
    override val descriptor: SerialDescriptor = SerialDescriptor("Asn1ElementDerEncodedSerializer", delegate.descriptor)

    override fun serialize(
        encoder: Encoder,
        value: Asn1Element
    ) {
        encoder.requireDerEncoder("Asn1ElementSerializer")
        encoder.encodeSerializableValue(delegate, value.derEncoded)
    }

    override fun deserialize(decoder: Decoder): Asn1Element {
        decoder.requireDerDecoder("Asn1ElementSerializer")
        return delegate.deserialize(decoder).let { Asn1Element.Companion.parse(it) }
    }

}

/**
 * ASN.1-specific serializer providing kotlinx-serialization support. Implement this on
 * companion objects of classes implementing [Asn1Encodable] and set it as the [Asn1Encodable]'s
 * serializer to get full kotlinx-serialization support!
 */
interface Asn1Serializer<A : Asn1Element, T : Asn1Encodable<A>> :
    Asn1Decodable<A, T>,
    KSerializer<T>,
    Asn1LeadingTagsDescriptor {

    /**
     * Leading ASN.1 tags this serializer can decode/encode.
     *
     * Use an empty set when leading tags cannot be inferred statically.
     */
    override val leadingTags: Set<Asn1Element.Tag>

    override val descriptor: SerialDescriptor
        get() = Asn1OpaqueSerializerDescriptor { leadingTags }

    override fun deserialize(decoder: Decoder): T {
        decoder.requireDerDecoder(descriptor.serialName)
        return ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
    }

    override fun serialize(encoder: Encoder, value: T) {
        encoder.requireDerEncoder(descriptor.serialName)
        encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
    }
}
