package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * See [COSE Algorithm Registry](https://www.iana.org/assignments/cose/cose.xhtml)
 */
@Serializable(with = CoseAlgorithmSerializer::class)
enum class CoseAlgorithm(val value: Int) : SpecializedDataIntegrityAlgorithm {

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


    companion object {
        /**
         * encompasses only signature algorithms, filtering out MACs
         */
        val signatureAlgorithms = listOf(
            ES256,
            ES384,
            ES512,

            PS256,
            PS384,
            PS512,

            RS256,
            RS384,
            RS512,
            RS1
        ).map { it.algorithm as SignatureAlgorithm }

        /**
         * encompasses only MACs, filtering out signature algorithms
         */
        val messageAuthenticationCodes = listOf(HS256, HS384, HS512).map { it.algorithm as MessageAuthenticationCode }


    }

    val digest: Digest
        get() = when (this) {
            RS1 -> Digest.SHA1
            ES256, HS256, PS256, RS256 -> Digest.SHA256
            ES384, HS384, PS384, RS384 -> Digest.SHA384
            ES512, HS512, PS512, RS512 -> Digest.SHA512
        }

    override val algorithm: DataIntegrityAlgorithm
        get() = when (this) {
            ES256 -> SignatureAlgorithm.ECDSA(Digest.SHA256, ECCurve.SECP_256_R_1)
            ES384 -> SignatureAlgorithm.ECDSA(Digest.SHA384, ECCurve.SECP_384_R_1)
            ES512 -> SignatureAlgorithm.ECDSA(Digest.SHA512, ECCurve.SECP_521_R_1)

            HS256, HS384, HS512 -> HMAC.byDigest(digest)
            PS256, PS384, PS512 -> SignatureAlgorithm.RSA(this.digest, RSAPadding.PSS)
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

fun SpecializedDataIntegrityAlgorithm.toJwsAlgorithm(): KmmResult<CoseAlgorithm> =
    if (this is DataIntegrityAlgorithm) (this as DataIntegrityAlgorithm).toCoseAlgorithm() else KmmResult.failure(
        IllegalArgumentException("Unsupported Algorithm: $this")
    )

/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun DataIntegrityAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm> = catching {
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

        is HMAC -> when (this.digest) {
            Digest.SHA256 -> CoseAlgorithm.HS256
            Digest.SHA384 -> CoseAlgorithm.HS384
            Digest.SHA512 -> CoseAlgorithm.HS512
            else -> throw IllegalArgumentException("HMAC with ${this.digest} is unsupported by COSE")
        }

        else -> throw IllegalArgumentException("UnsupportedAlgorithm $this")
    }
}

/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun SpecializedDataIntegrityAlgorithm.toCoseAlgorithm() =
    this.algorithm.toCoseAlgorithm()
