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

    @Serializable(with = JwaSerializer::class)
    class UNKNOWN(override val identifier: String) : JsonWebAlgorithm {
        override fun toString() = "Unknown JWA (identifier='$identifier')"
    }
}

object JwaSerializer : KSerializer<JsonWebAlgorithm> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("JwaSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): JsonWebAlgorithm {
        val decoded = decoder.decodeString()
        return kotlin.runCatching { JwsAlgorithm.entries.first { it.identifier == decoded } }
            .getOrElse {
                kotlin.runCatching {
                    JweAlgorithm.entries.first { it.identifier == decoded }
                }.getOrElse { JsonWebAlgorithm.UNKNOWN(decoded) }
            }
    }

    override fun serialize(encoder: Encoder, value: JsonWebAlgorithm) {
        encoder.encodeString(value.identifier)
    }

}