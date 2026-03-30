package at.asitplus.signum.indispensable.io

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Instant

/**
 * Serializes [Instant] as whole seconds from the Unix epoch.
 *
 * In JSON this is a NumericDate encoded as a JSON number (RFC 7519, Section 2).
 * In CBOR this is a CWT NumericDate encoded as an untagged CBOR numeric date, with
 * CBOR tag 1 omitted (RFC 8392, Section 2; RFC 8949, Section 3.4.2).
 */
object InstantLongSerializer : KSerializer<Instant> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("InstantLongSerializer", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): Instant {
        return Instant.fromEpochSeconds(decoder.decodeLong())
    }

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeLong(value.epochSeconds)
    }

}