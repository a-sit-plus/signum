package at.asitplus.crypto.datatypes.cose

import at.asitplus.crypto.datatypes.JwsAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = CoseAlgorithmSerializer::class)
enum class CoseAlgorithm(val value: Int) {

    // ECDSA with SHA-size
    ES256(-7),
    ES384(-35),
    ES512(-36),

    // HMAC-size with SHA-size
    HS256(5),
    HS384(6),
    HS512(7),

    // RSASSA-PSS with SHA-size
    PS256(-37),
    PS384(-38),
    PS512(-39),

    // RSASSA-PKCS1-v1_5 with SHA-size
    RS256(-257),
    RS384(-258),
    RS512(-259);

    fun toJwsAlgorithm() = when(this) {
        ES256 -> JwsAlgorithm.ES256
        ES384 -> JwsAlgorithm.ES384
        ES512 -> JwsAlgorithm.ES512

        HS256 -> JwsAlgorithm.HS256
        HS384 -> JwsAlgorithm.HS384
        HS512 -> JwsAlgorithm.HS512

        PS256 -> JwsAlgorithm.PS256
        PS384 -> JwsAlgorithm.PS384
        PS512 -> JwsAlgorithm.PS512

        RS256 -> JwsAlgorithm.RS256
        RS384 -> JwsAlgorithm.RS384
        RS512 -> JwsAlgorithm.RS512
    }

    val signatureValueLength
        get() = when (this) {
            ES256 -> 256 / 8 * 2
            ES384 -> 384 / 8 * 2
            ES512 -> 512 / 8 * 2
            HS256 -> 256 / 8
            HS384 -> 384 / 8
            HS512 -> 512 / 8
            else -> -1 // RSA signatures do not have a fixed size
        }
}


object CoseAlgorithmSerializer : KSerializer<CoseAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseAlgorithmSerializer", PrimitiveKind.INT)

    override fun serialize(encoder: Encoder, value: CoseAlgorithm) {
        value.let { encoder.encodeInt(it.value) }
    }

    override fun deserialize(decoder: Decoder): CoseAlgorithm {
        val decoded = decoder.decodeInt()
        return CoseAlgorithm.values().first { it.value == decoded }
    }

}