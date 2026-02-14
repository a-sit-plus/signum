package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException

/**
 * Tag-discriminated open polymorphism helper for ASN.1 DER.
 *
 * This serializer dispatches by leading ASN.1 tag at decode-time and by runtime value type at encode-time.
 * It is intended for open (non-sealed) polymorphic hierarchies where CHOICE-style tag dispatch is desired.
 */
open class Asn1TagDiscriminatedOpenPolymorphicSerializer<T : Any>(
    serialName: String,
    subtypes: List<SubtypeRegistration<T>>,
) : Asn1DiscriminatedOpenPolymorphicSerializer<T>(serialName) {

    private val dispatch = Asn1TagDiscriminatedDispatch(
        serialName = serialName,
        subtypes = subtypes,
    )

    override val leadingTags: Set<Asn1Element.Tag>
        get() = dispatch.leadingTags

    /**
     * Adds a new subtype registration after serializer construction.
     *
     * This is intentionally mutable to allow third-party libraries to extend open
     * ASN.1 polymorphic mappings in application code.
     */
    fun registerSubtype(registration: SubtypeRegistration<T>) {
        dispatch.registerSubtype(registration)
    }

    override fun serializerForEncode(value: T): KSerializer<out T> =
        dispatch.serializerForEncode(value)

    override fun serializerForDecode(decoder: DerDecoder): DeserializationStrategy<T> {
        val tag = decoder.peekCurrentElementTagOrNull()
            ?: throw SerializationException("No ASN.1 element left while decoding ${descriptor.serialName}")
        val selected = dispatch.serializerForDecode(tag)
        @Suppress("UNCHECKED_CAST")
        return selected as DeserializationStrategy<T>
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
