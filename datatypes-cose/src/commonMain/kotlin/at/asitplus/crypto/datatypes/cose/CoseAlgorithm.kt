package at.asitplus.crypto.datatypes.cose

import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.SpecializedSignatureAlgorithm
import at.asitplus.crypto.datatypes.X509SignatureAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = CoseAlgorithmSerializer::class)
enum class CoseAlgorithm(val value: Int): SpecializedSignatureAlgorithm {

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

    @Deprecated("COSE EC algorithms carry curve restrictions", ReplaceWith("algorithm"))
    fun toX509SignatureAlgorithm() = when (this) {
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

    val digest: Digest get() = when(this) {
        RS1 -> Digest.SHA1
        ES256, HS256, PS256, RS256 -> Digest.SHA256
        ES384, HS384, PS384, RS384 -> Digest.SHA384
        ES512, HS512, PS512, RS512 -> Digest.SHA512
    }

    override val algorithm: SignatureAlgorithm get() = when (this) {
        ES256 -> SignatureAlgorithm.ECDSA(Digest.SHA256, ECCurve.SECP_256_R_1)
        ES384 -> SignatureAlgorithm.ECDSA(Digest.SHA384, ECCurve.SECP_384_R_1)
        ES512 -> SignatureAlgorithm.ECDSA(Digest.SHA512, ECCurve.SECP_521_R_1)

        HS256, HS384, HS512 -> SignatureAlgorithm.HMAC(this.digest)
        PS256, PS384, PS512 -> SignatureAlgorithm.RSA(this. digest, RSAPadding.PKCS1)
        RS1, RS256, RS384, RS512 -> SignatureAlgorithm.RSA(this.digest, RSAPadding.PKCS1)
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

fun X509SignatureAlgorithm.toCoseAlgorithm() = when (this) {
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