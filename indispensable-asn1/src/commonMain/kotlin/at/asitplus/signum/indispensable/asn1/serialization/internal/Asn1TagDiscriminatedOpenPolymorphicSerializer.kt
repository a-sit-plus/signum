package at.asitplus.signum.indispensable.asn1.serialization.internal

import at.asitplus.signum.indispensable.asn1.Asn1Element
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException

internal class Asn1TagDiscriminatedOpenPolymorphicSerializer<T : Any>(
    serialName: String,
    subtypes: List<Asn1TagDiscriminatedSubtypeRegistration<T>>,
) : Asn1DiscriminatedOpenPolymorphicSerializer<T>(serialName) {

    private val dispatch = Asn1TagDiscriminatedDispatch(
        serialName = serialName,
        subtypes = subtypes,
    )

    override val leadingTags: Set<Asn1Element.Tag>
        get() = dispatch.leadingTags

    /**
     * Adds one subtype registration at runtime.
     *
     * @throws IllegalArgumentException on duplicate/invalid tag mapping
     */
    @Throws(IllegalArgumentException::class)
    fun registerSubtype(registration: Asn1TagDiscriminatedSubtypeRegistration<T>) {
        dispatch.registerSubtype(registration)
    }

    override fun serializerForEncode(encoder: DerEncoder, value: T): KSerializer<out T> =
        dispatch.serializerForEncode(value)

    /**
     * Selects decode serializer from current leading ASN.1 tag.
     *
     * @throws SerializationException when no current element exists or no subtype matches the tag
     */
    @Throws(SerializationException::class)
    override fun serializerForDecode(decoder: DerDecoder): DeserializationStrategy<T> {
        val tag = decoder.peekCurrentElementTagOrNull()
            ?: throw SerializationException("No ASN.1 element left while decoding ${descriptor.serialName}")
        val selected = dispatch.serializerForDecode(tag)
        @Suppress("UNCHECKED_CAST")
        return selected as DeserializationStrategy<T>
    }
}
