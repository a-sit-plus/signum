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

internal object Asn1ElementSerializer : KSerializer<Asn1Element> {
    private val delegate = ByteArraySerializer()
    override val descriptor: SerialDescriptor = SerialDescriptor("Asn1ElementDerEncodedSerializer", delegate.descriptor)

    override fun serialize(
        encoder: Encoder,
        value: Asn1Element
    ) {
        encoder.encodeSerializableValue(delegate, value.derEncoded)
    }

    override fun deserialize(decoder: Decoder): Asn1Element {
        return delegate.deserialize(decoder).let { Asn1Element.Companion.parse(it) }
    }

}

/**
 * ASN.1-specific serializer providing kotlinx-serialization support. Implement this on
 * companion objects of classes implementing [Asn1Encodable] and set it as the [Asn1Encodable]'s
 * serializer to get full kotlinx-serialization support!
 */
interface Asn1Serializer<A : Asn1Element, T : Asn1Encodable<A>> : Asn1Decodable<A, T>, KSerializer<T> {

    override val descriptor: SerialDescriptor
        get() = SerialDescriptor(
            this::class.qualifiedName ?: this::class.simpleName
            ?: throw IllegalArgumentException("passed Asn1Decodable has no name!"), ByteArraySerializer().descriptor
        )

    override fun deserialize(decoder: Decoder): T {
        return ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
    }

    override fun serialize(encoder: Encoder, value: T) {
        encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
    }
}