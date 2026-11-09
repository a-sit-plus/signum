package at.asitplus.signum.indispensable.io

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlin.math.floor
import kotlin.math.roundToLong
import kotlin.time.Instant

/**
 * Serializes [Instant] as seconds from the Unix epoch, i.e. a NumericDate.
 *
 * In JSON this is a NumericDate encoded as a JSON number (RFC 7519, Section 2).
 * In CBOR this is a CWT NumericDate encoded as an untagged CBOR numeric date, with
 * CBOR tag 1 omitted (RFC 8392, Section 2; RFC 8949, Section 3.4.2).
 *
 * Decoding accepts every representation these specifications allow:
 * - JSON: any JSON number, including fractions and exponents (e.g. `1700000000`, `1700000000.5`, `1.7e9`).
 *   For backwards compatibility, numbers wrapped in a JSON string (e.g. `"1700000000"`) are accepted, too.
 * - CBOR: unsigned or negative integers, as well as half-, single- and double-precision floats.
 *
 * Fractional seconds are retained when decoding. Encoding always produces whole seconds
 * ([Instant.epochSeconds]), so fractional seconds do not survive a decode/encode round trip.
 * Non-finite values (NaN, ±Infinity) and values outside the [Long] range are rejected.
 */
object InstantLongSerializer : KSerializer<Instant> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("InstantLongSerializer", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): Instant =
        if (decoder is JsonDecoder) decodeJson(decoder)
        else try {
            Instant.fromEpochSeconds(decoder.decodeLong())
        } catch (_: SerializationException) {
            // Not an integer, e.g. a CBOR float. This relies on the decoder not consuming the
            // offending data item when decodeLong() fails, which holds for kotlinx-serialization-cbor.
            // Switch to inspecting a CborElement once kotlinx-serialization-cbor provides one.
            decoder.decodeDouble().toInstant()
        }

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeLong(value.epochSeconds)
    }

    /** JSON number grammar (RFC 8259, Section 6), leniently allowing leading zeros. */
    private val jsonNumber = Regex("-?[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?")

    private fun decodeJson(decoder: JsonDecoder): Instant {
        val element = decoder.decodeJsonElement()
        if (element !is JsonPrimitive || element is JsonNull)
            throw SerializationException("Expected a NumericDate (JSON number), but got $element")
        val content = element.content
        if (!jsonNumber.matches(content))
            throw SerializationException("Expected a NumericDate (JSON number), but got $element")
        return content.toLongOrNull()?.let { Instant.fromEpochSeconds(it) }
            ?: content.toDouble().toInstant()
    }

    private fun Double.toInstant(): Instant {
        if (!isFinite() || this < Long.MIN_VALUE.toDouble() || this >= Long.MAX_VALUE.toDouble())
            throw SerializationException("NumericDate $this is not finite or out of range")
        val seconds = floor(this)
        val nanos = ((this - seconds) * 1_000_000_000).roundToLong()
        return Instant.fromEpochSeconds(seconds.toLong(), nanos)
    }
}
