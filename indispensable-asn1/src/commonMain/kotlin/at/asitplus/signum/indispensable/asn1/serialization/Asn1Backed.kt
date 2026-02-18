import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.serialization.DerDecoder
import at.asitplus.signum.indispensable.asn1.serialization.DerEncoder
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Wrapper that carries a decoded value plus optional raw ASN.1 TLV source.
 *
 * Equality/hashCode are based on [value] only; [asn1Element] is transport metadata.
 */
@Serializable(with = Asn1BackedSerializer::class)
data class Asn1Backed<T : Any> internal constructor(
    val value: T,
    @Transient val asn1Element: Asn1Element?
) {
    constructor(value: T) : this(value, null)

    override fun toString(): String {
        return "Asn1Backed(" +
                "value=$value, " +
                "asn1Element=${asn1Element?.prettyPrint()}" +
                ")"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1Backed<*>) return false

        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int = value.hashCode()

}
/**
 * Serializer for [Asn1Backed] that preserves raw ASN.1 element information in DER decode paths.
 */
class Asn1BackedSerializer<T : Any>(
    internal val valueSer: KSerializer<T>
) : KSerializer<Asn1Backed<T>> {

    // look like T to the format.
    override val descriptor: SerialDescriptor = valueSer.descriptor

    override fun deserialize(decoder: Decoder): Asn1Backed<T> {
        val raw = (decoder as? DerDecoder)?.peekCurrentElementOrNull()
        val v = decoder.decodeSerializableValue(valueSer)
        return Asn1Backed(v, raw)
    }

    override fun serialize(encoder: Encoder, value: Asn1Backed<T>) {
        encoder.encodeSerializableValue(valueSer, value.value)
    }
}
