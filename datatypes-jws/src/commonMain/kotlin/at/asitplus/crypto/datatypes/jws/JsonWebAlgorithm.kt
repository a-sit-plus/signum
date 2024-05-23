package at.asitplus.crypto.datatypes.jws

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = JwaSerializer::class)
interface JsonWebAlgorithm {
    val identifier: String

    companion object {
        val entries: List<JsonWebAlgorithm> = JwsAlgorithm.entries + JweAlgorithm.entries
    }
}

object JwaSerializer : KSerializer<JsonWebAlgorithm> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("JwaSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): JsonWebAlgorithm {
        val decoded = decoder.decodeString()
        return kotlin.runCatching { JwsAlgorithm.entries.first { it.identifier == decoded } }
            .getOrElse { JweAlgorithm.entries.first { it.identifier == decoded } }
    }

    override fun serialize(encoder: Encoder, value: JsonWebAlgorithm) {
        encoder.encodeString(value.identifier)
    }

}