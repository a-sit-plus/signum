package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Identifiable
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
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
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable(with = EcCurveSerializer::class)
enum class EcCurve(
    val jwkName: String,
    val keyLengthBits: UInt,
    val coordinateLengthBytes: UInt = keyLengthBits / 8u,
    val signatureLengthBytes: UInt = coordinateLengthBytes,
    override val oid: ObjectIdentifier
) : Identifiable {

    SECP_256_R_1("P-256", 256u, oid = KnownOIDs.prime256v1),
    SECP_384_R_1("P-384", 384u, oid = KnownOIDs.secp384r1),
    SECP_521_R_1("P-521", 521u, 66u, oid = KnownOIDs.secp521r1);

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
