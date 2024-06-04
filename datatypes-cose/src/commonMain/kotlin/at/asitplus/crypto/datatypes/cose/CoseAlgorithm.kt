package at.asitplus.crypto.datatypes.cose

import at.asitplus.crypto.datatypes.X509SignatureAlgorithm
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
        ES256 -> X509SignatureAlgorithm.ES256
        ES384 -> X509SignatureAlgorithm.ES384
        ES512 -> X509SignatureAlgorithm.ES512

        HS256 -> X509SignatureAlgorithm.HS256
        HS384 -> X509SignatureAlgorithm.HS384
        HS512 -> X509SignatureAlgorithm.HS512

        PS256 -> X509SignatureAlgorithm.PS256
        PS384 -> X509SignatureAlgorithm.PS384
        PS512 -> X509SignatureAlgorithm.PS512

        RS256 -> X509SignatureAlgorithm.RS256
        RS384 -> X509SignatureAlgorithm.RS384
        RS512 -> X509SignatureAlgorithm.RS512

        RS1 -> X509SignatureAlgorithm.RS1
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

fun X509SignatureAlgorithm.toCoseAlgorithm() = when(this) {
    X509SignatureAlgorithm.ES256 -> CoseAlgorithm.ES256
    X509SignatureAlgorithm.ES384 -> CoseAlgorithm.ES384
    X509SignatureAlgorithm.ES512 -> CoseAlgorithm.ES512

    X509SignatureAlgorithm.HS256 -> CoseAlgorithm.HS256
    X509SignatureAlgorithm.HS384 -> CoseAlgorithm.HS384
    X509SignatureAlgorithm.HS512 -> CoseAlgorithm.HS512

    X509SignatureAlgorithm.PS256 -> CoseAlgorithm.PS256
    X509SignatureAlgorithm.PS384 -> CoseAlgorithm.PS384
    X509SignatureAlgorithm.PS512 -> CoseAlgorithm.PS512

    X509SignatureAlgorithm.RS256 -> CoseAlgorithm.RS256
    X509SignatureAlgorithm.RS384 -> CoseAlgorithm.RS384
    X509SignatureAlgorithm.RS512 -> CoseAlgorithm.RS512

    X509SignatureAlgorithm.RS1 -> CoseAlgorithm.RS1
}