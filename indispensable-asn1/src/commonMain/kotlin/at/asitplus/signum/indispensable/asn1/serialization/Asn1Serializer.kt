package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.serialization.internal.requireDerDecoder
import at.asitplus.signum.indispensable.asn1.serialization.internal.requireDerEncoder
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * ASN.1-specific serializer providing kotlinx-serialization support. Implement this on
 * companion objects of classes implementing [Asn1Encodable] and set it as the [Asn1Encodable]'s
 * serializer to get full kotlinx-serialization support!
 */
interface Asn1Serializer<A : Asn1Element, T : Asn1Encodable<A>> :
    Asn1Decodable<A, T>,
    KSerializer<T> {

    /**
     * Leading ASN.1 tags this serializer can decode/encode.
     *
     * Use an empty set when leading tags cannot be inferred statically.
     */
    val leadingTags: Set<Asn1Element.Tag>

    override val descriptor: SerialDescriptor
        get() = Asn1OpaqueSerializerDescriptor { leadingTags }

    /**
     * Decodes one ASN.1-backed value via DER bytes.
     *
     * @throws SerializationException if decoder is not DER or ASN.1 decoding fails
     */
    @Throws(SerializationException::class)
    override fun deserialize(decoder: Decoder): T {
        decoder.requireDerDecoder(descriptor.serialName)
        return ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
    }

    /**
     * Encodes one ASN.1-backed value via DER bytes.
     *
     * @throws SerializationException if encoder is not DER
     */
    @Throws(SerializationException::class)
    override fun serialize(encoder: Encoder, value: T) {
        encoder.requireDerEncoder(descriptor.serialName)
        encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
    }
}