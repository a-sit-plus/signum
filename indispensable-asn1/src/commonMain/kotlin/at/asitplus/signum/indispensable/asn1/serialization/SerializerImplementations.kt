package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.encoding.parse
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
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
        encoder.requireAsn1Encoder("Asn1ElementSerializer")
        encoder.encodeSerializableValue(delegate, value.derEncoded)
    }

    override fun deserialize(decoder: Decoder): Asn1Element {
        decoder.requireAsn1Decoder("Asn1ElementSerializer")
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
            "Asn1DerSerializer", ByteArraySerializer().descriptor
        )

    override fun deserialize(decoder: Decoder): T {
        decoder.requireAsn1Decoder(descriptor.serialName)
        return ByteArraySerializer().deserialize(decoder).let { decodeFromDer(it) }
    }

    override fun serialize(encoder: Encoder, value: T) {
        encoder.requireAsn1Encoder(descriptor.serialName)
        encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToDer())
    }
}

private fun Encoder.requireAsn1Encoder(serializerName: String) {
    if (this !is DerEncoder) {
        throw SerializationException(
            "$serializerName supports ASN.1 DER format only. " +
                    "Use DER.encodeToDer(...) / DER.encodeToTlv(...) instead of non-ASN.1 formats."
        )
    }
}

private fun Decoder.requireAsn1Decoder(serializerName: String) {
    if (this !is DerDecoder) {
        throw SerializationException(
            "$serializerName supports ASN.1 DER format only. " +
                    "Use DER.decodeFromDer(...) / DER.decodeFromTlv(...) instead of non-ASN.1 formats."
        )
    }
}
