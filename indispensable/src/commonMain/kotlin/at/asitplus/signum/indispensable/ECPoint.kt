package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** A point with a curve-specific representation. */
interface ECPoint {
    val curve: ECCurve
}

object ECPointSerializer : KSerializer<ShortWeierstrassCurve.Point.Normalized> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ECPointSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ShortWeierstrassCurve.Point.Normalized) {
        encoder.encodeSerializableValue(ECCurveSerializer, value.curve)
        encoder.encodeSerializableValue(ByteArrayBase64Serializer, value.x.toByteArray())
        encoder.encodeBoolean(value.yCompressed == Sign.POSITIVE)
    }

    override fun deserialize(decoder: Decoder): ShortWeierstrassCurve.Point.Normalized {
        val curve = requireNotNull(decoder.decodeSerializableValue(ECCurveSerializer)).requireBuiltIn()
        val xBytes = decoder.decodeSerializableValue(ByteArrayBase64Serializer)
        val yIsPositive = decoder.decodeBoolean()
        return ShortWeierstrassCurve.Point.fromCompressed(curve, xBytes, yIsPositive)
    }

}
