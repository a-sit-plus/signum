package at.asitplus.crypto.datatypes.cose

import at.asitplus.crypto.datatypes.CryptoAlgorithm
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
    RS512(-259),

    // RSASSA-PKCS1-v1_5 using SHA-1
    RS1(-65535);


    fun toCryptoAlgorithm() = when(this) {
        ES256 -> CryptoAlgorithm.ES256
        ES384 -> CryptoAlgorithm.ES384
        ES512 -> CryptoAlgorithm.ES512

        HS256 -> CryptoAlgorithm.HS256
        HS384 -> CryptoAlgorithm.HS384
        HS512 -> CryptoAlgorithm.HS512

        PS256 -> CryptoAlgorithm.PS256
        PS384 -> CryptoAlgorithm.PS384
        PS512 -> CryptoAlgorithm.PS512

        RS256 -> CryptoAlgorithm.RS256
        RS384 -> CryptoAlgorithm.RS384
        RS512 -> CryptoAlgorithm.RS512

        RS1 -> CryptoAlgorithm.RS1
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
        return CoseAlgorithm.entries.first { it.value == decoded }
    }

}

fun CryptoAlgorithm.toCoseAlgorithm() = when(this) {
    CryptoAlgorithm.ES256 -> CoseAlgorithm.ES256
    CryptoAlgorithm.ES384 -> CoseAlgorithm.ES384
    CryptoAlgorithm.ES512 -> CoseAlgorithm.ES512

    CryptoAlgorithm.HS256 -> CoseAlgorithm.HS256
    CryptoAlgorithm.HS384 -> CoseAlgorithm.HS384
    CryptoAlgorithm.HS512 -> CoseAlgorithm.HS512

    CryptoAlgorithm.PS256 -> CoseAlgorithm.PS256
    CryptoAlgorithm.PS384 -> CoseAlgorithm.PS384
    CryptoAlgorithm.PS512 -> CoseAlgorithm.PS512

    CryptoAlgorithm.RS256 -> CoseAlgorithm.RS256
    CryptoAlgorithm.RS384 -> CoseAlgorithm.RS384
    CryptoAlgorithm.RS512 -> CoseAlgorithm.RS512

    CryptoAlgorithm.RS1 -> CoseAlgorithm.RS1
}