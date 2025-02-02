package at.asitplus.signum.indispensable.josef

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
 * Since we support only JWS algorithms (with one exception), this class is called what it's called.
 */
@Serializable(with = JwsAlgorithmSerializer::class)
enum class JwsAlgorithm(override val identifier: String) : JsonWebAlgorithm, SpecializedDataIntegrityAlgorithm {

    ES256("ES256"),
    ES384("ES384"),
    ES512("ES512"),

    HS256("HS256"),
    HS384("HS384"),
    HS512("HS512"),

    PS256("PS256"),
    PS384("PS384"),
    PS512("PS512"),

    RS256("RS256"),
    RS384("RS384"),
    RS512("RS512"),

    /**
     * The one exception, which is not a valid JWS algorithm identifier
     */
    NON_JWS_SHA1_WITH_RSA("RS1");


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
            NON_JWS_SHA1_WITH_RSA
        ).map { it.algorithm as SignatureAlgorithm }

        /**
         * Encompasses only MACs, filtering our signature algorithms
         */
        val messageAuthenticationCodes = listOf(HS256, HS384, HS512).map { it.algorithm as MessageAuthenticationCode }

    }

    val digest: Digest
        get() = when (this) {
            NON_JWS_SHA1_WITH_RSA -> Digest.SHA1
            ES256, HS256, PS256, RS256 -> Digest.SHA256
            ES384, HS384, PS384, RS384 -> Digest.SHA384
            ES512, HS512, PS512, RS512 -> Digest.SHA512
        }

    override val algorithm: DataIntegrityAlgorithm
        get() = when (this) {
            ES256, ES384, ES512 -> SignatureAlgorithm.ECDSA(this.digest, this.ecCurve!!)
            HS256, HS384, HS512 -> HMAC.byDigest(this.digest)
            PS256, PS384, PS512 -> SignatureAlgorithm.RSA(this.digest, RSAPadding.PSS)
            NON_JWS_SHA1_WITH_RSA, RS256, RS384, RS512 -> SignatureAlgorithm.RSA(this.digest, RSAPadding.PKCS1)
        }

    /** The curve to create signatures on.
     * This is fixed by RFC7518, as opposed to X.509 where other combinations are possible. */
    val ecCurve: ECCurve?
        get() = when (this) {
            ES256 -> ECCurve.SECP_256_R_1
            ES384 -> ECCurve.SECP_384_R_1
            ES512 -> ECCurve.SECP_521_R_1
            else -> null
        }
}

object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsAlgorithm) =
        JwaSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JwsAlgorithm {
        val decoded = decoder.decodeString()
        return JwsAlgorithm.entries.first { it.identifier == decoded }
    }
}


fun SpecializedDataIntegrityAlgorithm.toJwsAlgorithm(): KmmResult<JwsAlgorithm> =
    if (this is DataIntegrityAlgorithm) (this as DataIntegrityAlgorithm).toJwsAlgorithm() else KmmResult.failure(
        IllegalArgumentException("Unsupported Algorithm: $this")
    )

/** Tries to find a matching JWS algorithm. Note that JWS imposes curve restrictions on ECDSA based on the digest. */
fun DataIntegrityAlgorithm.toJwsAlgorithm(): KmmResult<JwsAlgorithm> = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA -> when (this.digest) {
            Digest.SHA256 -> JwsAlgorithm.ES256
            Digest.SHA384 -> JwsAlgorithm.ES384
            Digest.SHA512 -> JwsAlgorithm.ES512
            else -> throw IllegalArgumentException("ECDSA with ${this.digest} is unsupported by JWS")
        }

        is SignatureAlgorithm.RSA -> when (this.padding) {
            RSAPadding.PKCS1 -> when (this.digest) {
                Digest.SHA1 -> JwsAlgorithm.NON_JWS_SHA1_WITH_RSA
                Digest.SHA256 -> JwsAlgorithm.RS256
                Digest.SHA384 -> JwsAlgorithm.RS384
                Digest.SHA512 -> JwsAlgorithm.RS512
            }

            RSAPadding.PSS -> when (this.digest) {
                Digest.SHA256 -> JwsAlgorithm.PS256
                Digest.SHA384 -> JwsAlgorithm.PS384
                Digest.SHA512 -> JwsAlgorithm.PS512
                else -> throw IllegalArgumentException("RSA-PSS with ${this.digest} is unsupported by JWS")
            }

        }

        is HMAC -> when (this.digest) {
            Digest.SHA256 -> JwsAlgorithm.HS256
            Digest.SHA384 -> JwsAlgorithm.HS384
            Digest.SHA512 -> JwsAlgorithm.HS512
            else -> throw IllegalArgumentException("HMAC with ${this.digest} is unsupported by JWS")
        }

        else -> throw IllegalArgumentException("UnsupportedAlgorithm $this")

    }
}


