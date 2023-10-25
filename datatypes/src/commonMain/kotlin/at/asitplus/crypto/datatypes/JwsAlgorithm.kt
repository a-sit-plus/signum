package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
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
enum class JwsAlgorithm(val identifier: String, override val oid: ObjectIdentifier) : Asn1Encodable<Asn1Sequence>,
    Identifiable {

    // TODO double-check OID
    ES256("ES256", KnownOIDs.ecdsaWithSHA256),
    ES384("ES384", KnownOIDs.ecdsaWithSHA384),
    ES512("ES512", KnownOIDs.ecdsaWithSHA512),
    // TODO check OID
    HS256("HS256", KnownOIDs.hmacWithSHA256),
    HS384("HS384", KnownOIDs.sha384WithRSAEncryption),
    HS512("HS512", KnownOIDs.sha512WithRSAEncryption),
    // TODO check OID
    PS256("PS256", KnownOIDs.sha256WithRSAEncryption),
    PS384("PS384", KnownOIDs.sha384WithRSAEncryption),
    PS512("PS512", KnownOIDs.sha512WithRSAEncryption),
    // TODO check OID
    RS256("RS256", KnownOIDs.sha256WithRSAEncryption),
    RS384("RS384", KnownOIDs.sha384WithRSAEncryption),
    RS512("RS512", KnownOIDs.sha512WithRSAEncryption),

    /**
     * The one exception, which is not a valid JWS algorithm identifier
     */
    NON_JWS_SHA1_WITH_RSA("RS1", KnownOIDs.sha1WithRSAEncryption);

    val signatureValueLength
        get() = when (this) {
            ES256 -> 256 / 8
            ES384 -> 384 / 8
            ES512 -> 512 / 8
            HS256 -> 256 / 8
            else -> -1 //TODO("RS has no fixed size") TODO("HS and PS")

        }

    override fun encodeToTlv() = when (this) {
        ES256 -> asn1Sequence { append(oid) }
        ES384 -> asn1Sequence { append(oid) }
        ES512 -> asn1Sequence { append(oid) }

        HS256 -> TODO()//throw IllegalArgumentException("sigAlg: $this")
        HS384 -> TODO()
        HS512 -> TODO()

        PS256 -> TODO()
        PS384 -> TODO()
        PS512 -> TODO()

        RS256 -> asn1Sequence {
            append(oid) 
            asn1null()
        }

        RS384 -> asn1Sequence {
            append(oid) 
            asn1null()
        }

        RS512 -> asn1Sequence {
            append(oid) 
            asn1null()
        }

        NON_JWS_SHA1_WITH_RSA -> asn1Sequence {
            append(oid) 
            asn1null()
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, JwsAlgorithm> {
        override fun decodeFromTlv(src: Asn1Sequence): JwsAlgorithm {
            return when (val oid = (src.nextChild() as Asn1Primitive).readOid()) {
                ES512.oid -> ES512
                ES384.oid -> ES384
                ES256.oid -> ES256
                else -> {
                    val alg = when (oid) {
                        NON_JWS_SHA1_WITH_RSA.oid -> NON_JWS_SHA1_WITH_RSA
                        RS256.oid -> RS256
                        RS384.oid -> RS384
                        RS512.oid -> RS512
                        else -> TODO("Implement remaining algorithm oid: $oid")
                    }
                    if (src.nextChild().tag != BERTags.NULL) throw IllegalArgumentException("RSA Params not supported yet")
                    if (src.hasMoreChildren()) throw IllegalArgumentException("Superfluous Content in Signature")
                    alg
                }
            }
        }
    }
}

object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsAlgorithm) {
        value.let { encoder.encodeString(it.identifier) }
    }

    override fun deserialize(decoder: Decoder): JwsAlgorithm {
        val decoded = decoder.decodeString()
        return JwsAlgorithm.values().first { it.identifier == decoded }
    }
}
