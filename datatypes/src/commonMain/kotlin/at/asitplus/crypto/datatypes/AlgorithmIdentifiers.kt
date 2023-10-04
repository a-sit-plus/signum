package at.asitplus.crypto.datatypes

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = JwsAlgorithmSerializer::class)
enum class JwsAlgorithm(val identifier: String) {

    ES256("ES256"),
    ES384("ES384"),
    ES512("ES512"),
    HMAC256("HS256");

    val signatureValueLength
        get() = when (this) {
            ES256 -> 256 / 8
            ES384 -> 384 / 8
            ES512 -> 521 / 8
            HMAC256 -> 256 / 8
        }
}

object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsAlgorithm) {
        value.let { encoder.encodeString(it.identifier) }
    }

    override fun deserialize(decoder: Decoder): JwsAlgorithm {
        val decoded = decoder.decodeString()
        return JwsAlgorithm.values().first { it.identifier == decoded }
    }

}


enum class Digest {

    SHA256;

}