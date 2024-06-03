package at.asitplus.crypto.datatypes.jws

import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.asn1.Asn1.Null
import at.asitplus.crypto.datatypes.asn1.Asn1.Tagged
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
enum class JwsAlgorithm(override val identifier: String):JsonWebAlgorithm {

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

    fun toCryptoAlgorithm() = when (this) {
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

        NON_JWS_SHA1_WITH_RSA -> CryptoAlgorithm.RS1
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

fun CryptoAlgorithm.toJwsAlgorithm() = when (this) {
    CryptoAlgorithm.ES256 -> JwsAlgorithm.ES256
    CryptoAlgorithm.ES384 -> JwsAlgorithm.ES384
    CryptoAlgorithm.ES512 -> JwsAlgorithm.ES512

    CryptoAlgorithm.HS256 -> JwsAlgorithm.HS256
    CryptoAlgorithm.HS384 -> JwsAlgorithm.HS384
    CryptoAlgorithm.HS512 -> JwsAlgorithm.HS512

    CryptoAlgorithm.PS256 -> JwsAlgorithm.PS256
    CryptoAlgorithm.PS384 -> JwsAlgorithm.PS384
    CryptoAlgorithm.PS512 -> JwsAlgorithm.PS512

    CryptoAlgorithm.RS256 -> JwsAlgorithm.RS256
    CryptoAlgorithm.RS384 -> JwsAlgorithm.RS384
    CryptoAlgorithm.RS512 -> JwsAlgorithm.RS512

    CryptoAlgorithm.RS1 -> JwsAlgorithm.NON_JWS_SHA1_WITH_RSA
}