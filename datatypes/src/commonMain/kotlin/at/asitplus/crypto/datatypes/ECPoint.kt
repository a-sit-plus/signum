package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.ensureSize
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.misc.compressY
import at.asitplus.crypto.datatypes.misc.decompressY
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = ECPointSerializer::class)
data class ECPoint private constructor (val curve: ECCurve, val x: ModularBigInteger, val y: ModularBigInteger) {

    val xBytes get() = x.toByteArray().ensureSize(curve.coordinateLength.bytes)
    val yBytes get() = y.toByteArray().ensureSize(curve.coordinateLength.bytes)
    val yCompressed get() = compressY(curve, x, y)

    companion object {

        fun fromUncompressed(curve: ECCurve, x: ByteArray, y: ByteArray) =
            ECPoint(curve, curve.coordinateFromMagnitude(x), curve.coordinateFromMagnitude(y))

        fun fromCompressed(curve: ECCurve, x: ByteArray, root: Sign): ECPoint {
            val x = curve.coordinateFromMagnitude(x)
            val y = decompressY(curve, x, root)
            return ECPoint(curve, x, y)
        }

        fun fromCompressed(curve: ECCurve, x: ByteArray, usePositiveY: Boolean) =
            fromCompressed(curve, x, if (usePositiveY) Sign.POSITIVE else Sign.NEGATIVE)
    }
}

object ECPointSerializer : KSerializer<ECPoint> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ECPointSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ECPoint) {
        encoder.encodeSerializableValue(ECCurve.serializer(), value.curve)
        encoder.encodeSerializableValue(ByteArrayBase64Serializer, value.x.toByteArray())
        encoder.encodeSerializableValue(ByteArrayBase64Serializer, value.y.toByteArray())
    }

    override fun deserialize(decoder: Decoder): ECPoint {
        val curve = decoder.decodeSerializableValue(ECCurve.serializer())
        val xBytes = decoder.decodeSerializableValue(ByteArrayBase64Serializer)
        val yBytes = decoder.decodeSerializableValue(ByteArrayBase64Serializer)
        return ECPoint.fromUncompressed(curve, xBytes, yBytes)
    }

}
