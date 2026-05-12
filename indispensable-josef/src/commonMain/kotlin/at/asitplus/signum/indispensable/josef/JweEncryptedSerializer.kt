package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object JweEncryptedSerializer : KSerializer<JweEncrypted> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweEncryptedSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweEncrypted) {
        encoder.encodeString(value.serialize())
    }

    override fun deserialize(decoder: Decoder): JweEncrypted {
        return JweEncrypted.deserialize(decoder.decodeString()).getOrThrow()
    }
}