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

}
fun JwsAlgorithm.toCoseAlgorithm() = when (this) {
    JwsAlgorithm.ES256 -> CoseAlgorithm.ES256
    JwsAlgorithm.ES384 -> CoseAlgorithm.ES384
    JwsAlgorithm.ES512 -> CoseAlgorithm.ES512

    JwsAlgorithm.HS256 -> CoseAlgorithm.HS256
    JwsAlgorithm.HS384 -> CoseAlgorithm.HS384
    JwsAlgorithm.HS512 -> CoseAlgorithm.HS512

    JwsAlgorithm.PS256 -> CoseAlgorithm.PS256
    JwsAlgorithm.PS384 -> CoseAlgorithm.PS384
    JwsAlgorithm.PS512 -> CoseAlgorithm.PS512

    JwsAlgorithm.RS256 -> CoseAlgorithm.RS256
    JwsAlgorithm.RS384 -> CoseAlgorithm.RS384
    JwsAlgorithm.RS512 -> CoseAlgorithm.RS512
    JwsAlgorithm.NON_JWS_SHA1_WITH_RSA -> TODO()
}

object CoseAlgorithmSerializer : KSerializer<CoseAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseAlgorithmSerializer", PrimitiveKind.INT)

    override fun serialize(encoder: Encoder, value: CoseAlgorithm) {
        value.let { encoder.encodeInt(it.value) }
    }

    override fun deserialize(decoder: Decoder): CoseAlgorithm {
        val decoded = decoder.decodeInt()
        return CoseAlgorithm.entries.first { it.value == decoded }
    }

}