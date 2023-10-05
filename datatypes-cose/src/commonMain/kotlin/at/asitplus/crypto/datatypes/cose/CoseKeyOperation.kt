package at.asitplus.crypto.datatypes.cose

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = CoseKeyOperationSerializer::class)
enum class CoseKeyOperation(val value: Int) {

    SIGN(1),
    VERIFY(2),
    ENCRYPT(3),
    DECRYPT(4),
    WRAP_KEY(5),
    UNWRAP_KEY(6),
    DERIVE_KEY(7),
    DERIVE_BITS(8),
    MAC_CREATE(9),
    MAC_VERIFY(10);
}


object CoseKeyOperationSerializer : KSerializer<CoseKeyOperation> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseKeyOperationSerializer", PrimitiveKind.INT)

    override fun serialize(encoder: Encoder, value: CoseKeyOperation) {
        value.let { encoder.encodeInt(it.value) }
    }

    override fun deserialize(decoder: Decoder): CoseKeyOperation {
        val decoded = decoder.decodeInt()
        return CoseKeyOperation.values().first { it.value == decoded }
    }

}