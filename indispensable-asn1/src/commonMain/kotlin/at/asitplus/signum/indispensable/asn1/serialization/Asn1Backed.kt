import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.serialization.DerDecoder
import at.asitplus.signum.indispensable.asn1.serialization.DerEncoder
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Asn1BackedSerializer::class)
class Asn1Backed<T : Any> internal constructor(
    val value: T,
    @Transient val asn1Element: Asn1Element?
) {
    constructor(value: T) : this(value, null)

    companion object {
        fun <T : Any> serializer(valueSerializer: KSerializer<T>): KSerializer<Asn1Backed<T>> =
            Asn1BackedSerializer(valueSerializer)
    }
}

class Asn1BackedSerializer<T : Any>(
    private val valueSer: KSerializer<T>
) : KSerializer<Asn1Backed<T>> {

    // look like T to the format.
    override val descriptor: SerialDescriptor = valueSer.descriptor

    override fun deserialize(decoder: Decoder): Asn1Backed<T> {
        val raw = (decoder as? DerDecoder)?.peekCurrentElementOrNull()
        val v = valueSer.deserialize(decoder)
        return Asn1Backed(v, raw)
    }

    override fun serialize(encoder: Encoder, value: Asn1Backed<T>) {

        if ((encoder is DerEncoder) &&
            (encoder.formatConfiguration.reEmitAsn1Backed && value.asn1Element != null)
        ) encoder.appendElement(value.asn1Element)
        else valueSer.serialize(encoder, value.value)


    }
}
