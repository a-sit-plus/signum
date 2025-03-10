package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1GeneralizedTimePrimitive
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1UtcTimePrimitive
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInstant
import kotlinx.datetime.Instant
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * ASN.1 TIME (required since GENERALIZED TIME and UTC TIME exist)
 *
 * @param instant the timestamp to encode
 * @param formatOverride to force either  GENERALIZED TIME or UTC TIME
 */
@Serializable(with = Asn1TimeSerializer::class)
class Asn1Time(instant: Instant, formatOverride: Format? = null) : Asn1Encodable<Asn1Primitive> {

    val instant = Instant.fromEpochSeconds(instant.epochSeconds)

    /**
     * Indicates whether this timestamp uses UTC TIME or GENERALIZED TIME
     */
    val format: Format =
        formatOverride ?: if (this.instant > THRESHOLD_GENERALIZED_TIME) Format.GENERALIZED else Format.UTC

    companion object : Asn1Decodable<Asn1Primitive, Asn1Time> {
        private val THRESHOLD_GENERALIZED_TIME = Instant.parse("2050-01-01T00:00:00Z")

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Primitive) =
            Asn1Time(src.decodeToInstant(), if (src.tag == Asn1Element.Tag.TIME_UTC) Format.UTC else Format.GENERALIZED)
    }

    override fun encodeToTlv(): Asn1Primitive =
        when (format) {
            Format.UTC -> instant.encodeToAsn1UtcTimePrimitive()
            Format.GENERALIZED -> instant.encodeToAsn1GeneralizedTimePrimitive()
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Asn1Time

        if (instant != other.instant) return false
        if (format != other.format) return false

        return true
    }

    override fun hashCode(): Int {
        var result = instant.hashCode()
        result = 31 * result + format.hashCode()
        return result
    }

    override fun toString(): String {
        return "Asn1Time(instant=$instant, format=$format)"
    }

    /**
     * Enum of supported Time formats
     */
    enum class Format {
        /**
         * UTC TIME
         */
        UTC,

        /**
         * GENERALIZED TIME
         */
        GENERALIZED
    }
}


object Asn1TimeSerializer : KSerializer<Asn1Time> {
    override val descriptor = PrimitiveSerialDescriptor("Asn1Time", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder) =
        Asn1Time.decodeFromTlv(Asn1Element.parseFromDerHexString(decoder.decodeString()) as Asn1Primitive)

    override fun serialize(encoder: Encoder, value: Asn1Time) {
        encoder.encodeString(value.encodeToTlv().toDerHexString())
    }

}