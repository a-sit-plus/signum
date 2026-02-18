package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Structure
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.readOid
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal class Asn1OidDiscriminatedOpenPolymorphicSerializer<T : Any>(
    serialName: String,
    subtypes: List<Asn1OidDiscriminatedSubtypeRegistration<T>>,
    private val oidSelector: (Asn1Element) -> ObjectIdentifier? = ::oidFrom,
) : Asn1DiscriminatedOpenPolymorphicSerializer<T>(serialName) {

    private val dispatch = Asn1OidDiscriminatedDispatch(
        serialName = serialName,
        subtypes = subtypes,
    )

    override val leadingTags: Set<Asn1Element.Tag>
        get() = dispatch.leadingTags

    /**
     * Adds one subtype registration at runtime.
     *
     * @throws IllegalArgumentException on duplicate/invalid OID mapping
     */
    @Throws(IllegalArgumentException::class)
    fun registerSubtype(registration: Asn1OidDiscriminatedSubtypeRegistration<T>) {
        dispatch.registerSubtype(registration)
    }

    override fun serializerForEncode(encoder: DerEncoder,value: T): KSerializer<out T> =
        dispatch.registrationForEncode(value).also {
            encoder.prependOidToNextStructure(it.oid)
        }.serializer

    /**
     * Selects decode serializer by extracting discriminator OID from current ASN.1 element.
     *
     * @throws SerializationException if no current element exists, OID extraction fails, or no subtype is registered
     */
    @Throws(SerializationException::class)
    override fun serializerForDecode(decoder: DerDecoder): DeserializationStrategy<T> {
        val element = decoder.peekCurrentElementOrNull()
            ?: throw SerializationException("No ASN.1 element left while decoding ${descriptor.serialName}")
        val oid = oidSelector(element)
            ?: throw SerializationException(
                "Could not extract discriminator OID from current ASN.1 element while decoding ${descriptor.serialName}"
            )
        val selected = dispatch.serializerForDecode(oid)
        decoder.dropOidFromNextStructure()
        @Suppress("UNCHECKED_CAST")
        return selected as DeserializationStrategy<T>
    }

    /**
     * Serializes [value] and prepends OID discriminator to the next encoded structure.
     *
     * @throws SerializationException if encoder is not DER or runtime subtype matching is ambiguous/missing
     */
    @Throws(SerializationException::class)
    override fun serialize(encoder: Encoder, value: T) {
        val derEncoder = encoder as? DerEncoder
            ?: throw SerializationException("Expected DerEncoder while encoding ${descriptor.serialName}")

        val reg = dispatch.registrationForEncode(value)
        derEncoder.prependOidToNextStructure(reg.oid)

        @Suppress("UNCHECKED_CAST")
        val ser = reg.serializer as KSerializer<T>
        derEncoder.encodeSerializableValue(ser, value)
    }


}

/**
 * Default OID selector for OID-discriminated open polymorphism.
 *
 * This covers the common shape `SEQUENCE { OBJECT IDENTIFIER, ... }`
 */
internal fun oidFrom(element: Asn1Element): ObjectIdentifier? {

    val structure = element as? Asn1Structure ?: return null

    val primitive = structure.firstOrNull() as? Asn1Primitive
    if (primitive?.tag == Asn1Element.Tag.OID) {
        return runCatching { primitive.readOid() }.getOrNull()
    }


    return null
}

internal fun inferOpenPolymorphicSubtypeLeadingTagsOrNull(
    descriptor: SerialDescriptor,
): Set<Asn1Element.Tag>? = when (val resolution = descriptor.possibleLeadingTagsForAsn1()) {
    is Asn1LeadingTagsResolution.Exact -> resolution.tags
    Asn1LeadingTagsResolution.UnknownInfer -> null
}

internal fun cannotInferOpenPolymorphicSubtypeLeadingTagsMessage(
    serialName: String,
): String =
    "Cannot infer leading ASN.1 tag(s) for subtype '$serialName'. " +
            "Provide leadingTags explicitly."
