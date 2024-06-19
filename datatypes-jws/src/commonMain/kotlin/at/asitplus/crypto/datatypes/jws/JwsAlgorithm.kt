package at.asitplus.crypto.datatypes.jws

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


/**
 * Since we support only JWS algorithms (with one exception), this class is called what it's called.
 */
@Serializable(with = JwsAlgorithmSerializer::class)
enum class JwsAlgorithm(override val identifier: String) : JsonWebAlgorithm, SpecializedSignatureAlgorithm {

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

    val digest: Digest get() = when(this) {
        NON_JWS_SHA1_WITH_RSA -> Digest.SHA1
        ES256, HS256, PS256, RS256 -> Digest.SHA256
        ES384, HS384, PS384, RS384 -> Digest.SHA384
        ES512, HS512, PS512, RS512 -> Digest.SHA512
    }

    @Deprecated("JWS EC algorithms carry curve restrictions", ReplaceWith("algorithm"))
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

        NON_JWS_SHA1_WITH_RSA -> X509SignatureAlgorithm.RS1
    }

    override val algorithm: SignatureAlgorithm get() = when (this) {
        ES256, ES384, ES512 -> SignatureAlgorithm.ECDSA(this.digest, this.ecCurve!!)
        HS256, HS384, HS512 -> SignatureAlgorithm.HMAC(this.digest)
        PS256, PS384, PS512 -> SignatureAlgorithm.RSA(this. digest, RSAPadding.PKCS1)
        NON_JWS_SHA1_WITH_RSA, RS256, RS384, RS512 -> SignatureAlgorithm.RSA(this.digest, RSAPadding.PKCS1)
    }

    /** The curve to create signatures on.
     * This is fixed by RFC7518, as opposed to X.509 where other combinations are possible. */
    val ecCurve: ECCurve? get() = when (this) {
        ES256 -> ECCurve.SECP_256_R_1
        ES384 -> ECCurve.SECP_384_R_1
        ES512 -> ECCurve.SECP_521_R_1
        else -> null
    }
}

object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsAlgorithm) = JwaSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JwsAlgorithm {
        val decoded = decoder.decodeString()
        return JwsAlgorithm.entries.first { it.identifier == decoded }
    }
}

@Deprecated("X509 and JWS are not equivalent; JWS carries curve restrictions.", ReplaceWith("algorithm"))
fun X509SignatureAlgorithm.toJwsAlgorithm() = when (this) {
    X509SignatureAlgorithm.ES256 -> JwsAlgorithm.ES256
    X509SignatureAlgorithm.ES384 -> JwsAlgorithm.ES384
    X509SignatureAlgorithm.ES512 -> JwsAlgorithm.ES512

    X509SignatureAlgorithm.HS256 -> JwsAlgorithm.HS256
    X509SignatureAlgorithm.HS384 -> JwsAlgorithm.HS384
    X509SignatureAlgorithm.HS512 -> JwsAlgorithm.HS512

    X509SignatureAlgorithm.PS256 -> JwsAlgorithm.PS256
    X509SignatureAlgorithm.PS384 -> JwsAlgorithm.PS384
    X509SignatureAlgorithm.PS512 -> JwsAlgorithm.PS512

    X509SignatureAlgorithm.RS256 -> JwsAlgorithm.RS256
    X509SignatureAlgorithm.RS384 -> JwsAlgorithm.RS384
    X509SignatureAlgorithm.RS512 -> JwsAlgorithm.RS512

    X509SignatureAlgorithm.RS1 -> JwsAlgorithm.NON_JWS_SHA1_WITH_RSA
}