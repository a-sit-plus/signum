package at.asitplus.crypto.datatypes.jws

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = JwkTypeSerializer::class)
enum class JwkType(val text: String) {

    EC("EC"),
    RSA("RSA");

}

object JwkTypeSerializer : KSerializer<JwkType?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwkTypeSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwkType?) {
        value?.let { encoder.encodeString(it.text) }
    }

    override fun deserialize(decoder: Decoder): JwkType? {
        val decoded = decoder.decodeString()
        return JwkType.values().firstOrNull { it.text == decoded }
    }
}