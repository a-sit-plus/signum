package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.serialization.withAsn1LeadingTags
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal fun contextTag(value: ULong) =
    Asn1Element.Tag(value, constructed = false, TagClass.CONTEXT_SPECIFIC)

abstract class AbstractX509GeneralName(
    final override val type: GeneralName.NameType,
    final override val asn1Representation: Asn1Element,
) : GeneralName.X509Representable {

    override fun equals(other: Any?): Boolean =
        other is GeneralName.X509Representable &&
                type == other.type && asn1Representation == other.asn1Representation

    override fun hashCode(): Int = 31 * type.hashCode() + asn1Representation.hashCode()
}

internal object GeneralNameSerializer : KSerializer<GeneralName> {
    private val delegate = Asn1Element.serializer()
    private val leadingTags = GeneralName.NameType.entries.flatMap {
        listOf(contextTag(it.value), Asn1Element.Tag(it.value, constructed = true, TagClass.CONTEXT_SPECIFIC))
    }.toSet()

    override val descriptor = SerialDescriptor(
        "at.asitplus.signum.indispensable.pki.x500.X509GeneralName",
        delegate.descriptor,
    ).withAsn1LeadingTags(leadingTags)

    override fun serialize(encoder: Encoder, value: GeneralName) =
        encoder.encodeSerializableValue(
            delegate,
            (value as? GeneralName.X509Representable
                ?: throw Asn1Exception("GeneralName has no X.509/DER representation")).asn1Representation,
        )

    override fun deserialize(decoder: Decoder): GeneralName {
        val src = decoder.decodeSerializableValue(delegate)
        val type = GeneralName.NameType.fromTagValue(src.tag.tagValue)
            ?: throw Asn1Exception("Unsupported GeneralName tag ${src.tag}")
        return GeneralName.X509Representable.fromAsn1Representation(type, src)
    }
}

internal object GeneralNameListSerializer : KSerializer<List<GeneralName>> by ListSerializer(GeneralNameSerializer)
