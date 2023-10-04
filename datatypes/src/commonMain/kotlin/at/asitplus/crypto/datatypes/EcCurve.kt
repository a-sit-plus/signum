package at.asitplus.crypto.datatypes

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * EC Curve Class [jwkName] really does use established JWK curve names
 */
@Serializable(with = EcCurveSerializer::class)
enum class EcCurve(
    val jwkName: String,
    val keyLengthBits: UInt,
    val coordinateLengthBytes: UInt = keyLengthBits / 8u,
    val signatureLengthBytes: UInt = coordinateLengthBytes
) {

    SECP_256_R_1("P-256", 256u),
    SECP_384_R_1("P-384", 384u),
    SECP_521_R_1("P-521", 521u, 66u);

    companion object {
        fun of(bits: UInt) = entries.find { it.keyLengthBits == bits }
    }

}

object EcCurveSerializer : KSerializer<EcCurve> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("EcCurveSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: EcCurve) {
        encoder.encodeString(value.jwkName)
    }

    override fun deserialize(decoder: Decoder): EcCurve {
        val decoded = decoder.decodeString()
        return EcCurve.entries.firstOrNull { it.jwkName == decoded }
            ?: throw Throwable("Unsupported EC Curve Type $decoded")
    }

}