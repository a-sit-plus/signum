package at.asitplus.signum.indispensable.asn1.serialization

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

    fun registerSubtype(registration: Asn1TagDiscriminatedSubtypeRegistration<T>) {
        dispatch.registerSubtype(registration)
    }

    override fun serializerForEncode(encoder: DerEncoder, value: T): KSerializer<out T> =
        dispatch.serializerForEncode(value)

    override fun serializerForDecode(decoder: DerDecoder): DeserializationStrategy<T> {
        val tag = decoder.peekCurrentElementTagOrNull()
            ?: throw SerializationException("No ASN.1 element left while decoding ${descriptor.serialName}")
        val selected = dispatch.serializerForDecode(tag)
        @Suppress("UNCHECKED_CAST")
        return selected as DeserializationStrategy<T>
    }
}
