@file:OptIn(
    kotlinx.serialization.SealedSerializationApi::class,
)

package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.serialization.internal.requireDerDecoder
import at.asitplus.signum.indispensable.asn1.serialization.internal.requireDerEncoder
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal interface Asn1LeadingTagsDescriptor {
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

internal open class Asn1LeadingTagsSerialDescriptor(
    private val delegate: SerialDescriptor,
    private val leadingTagsProvider: () -> Set<Asn1Element.Tag>,
) : SerialDescriptor by delegate, Asn1LeadingTagsDescriptor {
    override val leadingTags: Set<Asn1Element.Tag>
        get() = leadingTagsProvider()

    override val annotations: List<Annotation>
        get() = delegate.annotations + Asn1LeadingTagsAnnotation(leadingTagsProvider)
}

internal class Asn1OpaqueSerializerDescriptor(
    leadingTagsProvider: () -> Set<Asn1Element.Tag>,
) : Asn1LeadingTagsSerialDescriptor(asn1OpaqueDelegateDescriptor, leadingTagsProvider)

internal fun SerialDescriptor.withAsn1LeadingTags(leadingTags: Set<Asn1Element.Tag>): SerialDescriptor =
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

    /**
     * Serializes an already materialized ASN.1 element as DER bytes.
     *
     * @throws kotlinx.serialization.SerializationException if encoder is not DER
     */
    @Throws(kotlinx.serialization.SerializationException::class)
    override fun serialize(
        encoder: Encoder,
        value: Asn1Element
    ) {
        encoder.requireDerEncoder("Asn1ElementSerializer")
        encoder.encodeSerializableValue(delegate, value.derEncoded)
    }

    /**
     * Deserializes DER bytes into an ASN.1 element.
     *
     * @throws kotlinx.serialization.SerializationException if decoder is not DER or input bytes are invalid ASN.1 DER
     */
    @Throws(kotlinx.serialization.SerializationException::class)
    override fun deserialize(decoder: Decoder): Asn1Element {
        decoder.requireDerDecoder("Asn1ElementSerializer")
        return delegate.deserialize(decoder).let { Asn1Element.Companion.parse(it) }
    }

}

