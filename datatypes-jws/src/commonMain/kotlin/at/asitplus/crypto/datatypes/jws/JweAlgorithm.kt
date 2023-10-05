package at.asitplus.crypto.datatypes.jws

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = JweAlgorithmSerializer::class)
enum class JweAlgorithm(val text: String) {

    ECDH_ES("ECDH-ES");

}

object JweAlgorithmSerializer : KSerializer<JweAlgorithm?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweAlgorithm?) {
        value?.let { encoder.encodeString(it.text) }
    }

    override fun deserialize(decoder: Decoder): JweAlgorithm? {
        val decoded = decoder.decodeString()
        return JweAlgorithm.values().firstOrNull { it.text == decoded }
    }

}