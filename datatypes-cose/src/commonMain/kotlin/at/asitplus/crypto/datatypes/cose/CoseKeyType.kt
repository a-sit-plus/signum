package at.asitplus.crypto.datatypes.cose

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = CoseKeyTypeSerializer::class)
enum class CoseKeyType(val value: Int) {
    OKP(1),
    EC2(2),
    RSA(3),
    SYMMETRIC(4),
    RESERVED(0)
}

object CoseKeyTypeSerializer : KSerializer<CoseKeyType> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseKeyTypeSerializer", PrimitiveKind.INT)

    override fun serialize(encoder: Encoder, value: CoseKeyType) {
        value.let { encoder.encodeInt(it.value) }
    }

    override fun deserialize(decoder: Decoder): CoseKeyType {
        val decoded = decoder.decodeInt()
        return CoseKeyType.values().firstOrNull { it.value == decoded }
            ?: throw IllegalArgumentException("Not known: $decoded")
    }
}