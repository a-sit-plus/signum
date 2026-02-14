package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Tag-discriminated open polymorphism helper for ASN.1 DER.
 *
 * This serializer dispatches by leading ASN.1 tag at decode-time and by runtime value type at encode-time.
 * It is intended for open (non-sealed) polymorphic hierarchies where CHOICE-style tag dispatch is desired.
 */
open class Asn1TagDiscriminatedOpenPolymorphicSerializer<T : Any>(
    serialName: String,
    subtypes: List<SubtypeRegistration<T>>,
) : KSerializer<T>, Asn1LeadingTagsDescriptor {

    private val registrations = mutableListOf<SubtypeRegistration<T>>()
    private val deserializersByTag = linkedMapOf<Asn1Element.Tag, KSerializer<out T>>()

    override val leadingTags: Set<Asn1Element.Tag>
        get() = deserializersByTag.keys

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(serialName, PrimitiveKind.STRING)
            .withDynamicAsn1LeadingTags { leadingTags }

    init {
        require(subtypes.isNotEmpty()) { "At least one subtype registration is required" }
        subtypes.forEach(::registerSubtype)
    }

    /**
     * Adds a new subtype registration after serializer construction.
     *
     * This is intentionally mutable to allow third-party libraries to extend open
     * ASN.1 polymorphic mappings in application code.
     */
    fun registerSubtype(registration: SubtypeRegistration<T>) {
        require(registration.leadingTags.isNotEmpty()) {
            "Subtype '${registration.debugName}' must declare at least one leading ASN.1 tag"
        }
        registration.leadingTags.forEach { tag ->
            val existing = deserializersByTag[tag]
            if (existing != null) {
                throw IllegalArgumentException(
                    "Duplicate tag mapping for $tag in ${descriptor.serialName}: " +
                            "${existing.descriptor.serialName} and ${registration.serializer.descriptor.serialName}"
                )
            }
        }
        registrations += registration
        registration.leadingTags.forEach { tag ->
            deserializersByTag[tag] = registration.serializer
        }
    }

    override fun serialize(encoder: Encoder, value: T) {
        if (encoder !is DerEncoder) {
            throw SerializationException(
                "${descriptor.serialName} supports ASN.1 DER format only. " +
                        "Use DER.encodeToDer(...) / DER.encodeToTlv(...) instead of non-ASN.1 formats."
            )
        }
        val matches = registrations.filter { it.matches(value) }
        val selected = when (matches.size) {
            1 -> matches.single().serializer
            0 -> throw SerializationException(
                "No registered open-polymorphic subtype matches runtime value ${value::class} " +
                        "for ${descriptor.serialName}"
            )

            else -> throw SerializationException(
                "Multiple registered open-polymorphic subtypes match runtime value ${value::class} " +
                        "for ${descriptor.serialName}: ${matches.joinToString { it.debugName }}"
            )
        }
        @Suppress("UNCHECKED_CAST")
        encoder.encodeSerializableValue(selected as KSerializer<Any?>, value as Any?)
    }

    override fun deserialize(decoder: Decoder): T {
        if (decoder !is DerDecoder) {
            throw SerializationException(
                "${descriptor.serialName} supports ASN.1 DER format only. " +
                        "Use DER.decodeFromDer(...) / DER.decodeFromTlv(...) instead of non-ASN.1 formats."
            )
        }
        val tag = decoder.peekCurrentElementTagOrNull()
            ?: throw SerializationException("No ASN.1 element left while decoding ${descriptor.serialName}")
        val selected = deserializersByTag[tag]
            ?: throw SerializationException(
                "No registered open-polymorphic subtype in ${descriptor.serialName} for leading tag $tag"
            )
        @Suppress("UNCHECKED_CAST")
        return decoder.decodeCurrentElementWith(selected as DeserializationStrategy<T>)
    }

    data class SubtypeRegistration<T : Any>(
        internal val serializer: KSerializer<out T>,
        internal val leadingTags: Set<Asn1Element.Tag>,
        internal val matches: (T) -> Boolean,
        internal val debugName: String,
    )
}

inline fun <T : Any, reified S : T> asn1OpenPolymorphicSubtype(
    serializer: KSerializer<S>,
    vararg leadingTags: Asn1Element.Tag,
): Asn1TagDiscriminatedOpenPolymorphicSerializer.SubtypeRegistration<T> =
    asn1OpenPolymorphicSubtype(serializer, leadingTags.toSet())

inline fun <T : Any, reified S : T> asn1OpenPolymorphicSubtype(
    serializer: KSerializer<S>,
    leadingTags: Set<Asn1Element.Tag>,
): Asn1TagDiscriminatedOpenPolymorphicSerializer.SubtypeRegistration<T> =
    Asn1TagDiscriminatedOpenPolymorphicSerializer.SubtypeRegistration(
        serializer = serializer,
        leadingTags = leadingTags,
        matches = { it is S },
        debugName = serializer.descriptor.serialName
    )

inline fun <T : Any, reified S : T> Asn1TagDiscriminatedOpenPolymorphicSerializer<T>.registerSubtype(
    serializer: KSerializer<S>,
    vararg leadingTags: Asn1Element.Tag,
) {
    registerSubtype(
        asn1OpenPolymorphicSubtype(
            serializer = serializer,
            leadingTags = leadingTags.toSet(),
        )
    )
}
