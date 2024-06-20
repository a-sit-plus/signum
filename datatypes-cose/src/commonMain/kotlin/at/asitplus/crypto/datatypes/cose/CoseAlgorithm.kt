package at.asitplus.crypto.datatypes.cose

import at.asitplus.catching
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.SpecializedSignatureAlgorithm
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
        PS256, PS384, PS512 -> SignatureAlgorithm.RSA(this. digest, RSAPadding.PSS)
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

/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun SignatureAlgorithm.toCoseAlgorithm() = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA -> when (this.digest) {
            Digest.SHA256 -> CoseAlgorithm.ES256
            Digest.SHA384 -> CoseAlgorithm.ES384
            Digest.SHA512 -> CoseAlgorithm.ES512
            else -> throw IllegalArgumentException("ECDSA with ${this.digest} is unsupported by COSE")
        }
        is SignatureAlgorithm.RSA -> when (this.padding) {
            RSAPadding.PKCS1 -> when (this.digest) {
                Digest.SHA1 -> CoseAlgorithm.RS1
                Digest.SHA256 -> CoseAlgorithm.RS256
                Digest.SHA384 -> CoseAlgorithm.RS384
                Digest.SHA512 -> CoseAlgorithm.RS512
            }
            RSAPadding.PSS -> when (this.digest) {
                Digest.SHA256 -> CoseAlgorithm.PS256
                Digest.SHA384 -> CoseAlgorithm.PS384
                Digest.SHA512 -> CoseAlgorithm.PS512
                else -> throw IllegalArgumentException("RSA-PSS with ${this.digest} is unsupported by COSE")
            }
        }
        is SignatureAlgorithm.HMAC -> when (this.digest) {
            Digest.SHA256 -> CoseAlgorithm.HS256
            Digest.SHA384 -> CoseAlgorithm.HS384
            Digest.SHA512 -> CoseAlgorithm.HS512
            else -> throw IllegalArgumentException("HMAC with ${this.digest} is unsupported by COSE")
        }
    }
}

/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun SpecializedSignatureAlgorithm.toCoseAlgorithm() =
    this.algorithm.toCoseAlgorithm()
