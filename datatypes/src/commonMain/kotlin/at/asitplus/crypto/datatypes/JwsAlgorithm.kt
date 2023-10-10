package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = JwsAlgorithmSerializer::class)
enum class JwsAlgorithm(val identifier: String) : Asn1Encodable<Asn1Sequence> {

    ES256("ES256"),
    ES384("ES384"),
    ES512("ES512"),
    RS256("RS256"),
    RS384("RS384"),
    RS512("RS512"),
    UNOFFICIAL_RSA_SHA1("RS1"),
    HMAC256("HS256");

    val signatureValueLength
        get() = when (this) {
            ES256 -> 256 / 8
            ES384 -> 384 / 8
            ES512 -> 512 / 8
            HMAC256 -> 256 / 8
            else -> -1 //TODO("RSA has no fixed size???")
        }

    override fun encodeToTlv() = when (this) {
        ES256 -> asn1Sequence { oid { KnownOIDs.ecdsaWithSHA256 } }
        ES384 -> asn1Sequence { oid { KnownOIDs.ecdsaWithSHA384 } }
        ES512 -> asn1Sequence { oid { KnownOIDs.ecdsaWithSHA512 } }
        RS256 -> asn1Sequence {
            oid { KnownOIDs.sha256WithRSAEncryption }
            asn1null()
        }

        RS384 -> asn1Sequence {
            oid { KnownOIDs.sha384WithRSAEncryption }
            asn1null()
        }

        RS512 -> asn1Sequence {
            oid { KnownOIDs.sha512WithRSAEncryption }
            asn1null()
        }

        UNOFFICIAL_RSA_SHA1 -> asn1Sequence {
            oid { KnownOIDs.sha1WithRSAEncryption }
            asn1null()
        }

        HMAC256 -> throw IllegalArgumentException("sigAlg: $this")
    }

    companion object:Asn1Decodable<Asn1Sequence,JwsAlgorithm>{
        override fun decodeFromTlv(input: Asn1Sequence): JwsAlgorithm {
            return when (val oid = (input.nextChild() as Asn1Primitive).readOid()) {
                KnownOIDs.ecdsaWithSHA512 -> ES512
                KnownOIDs.ecdsaWithSHA384 -> ES384
                KnownOIDs.ecdsaWithSHA256 -> ES256
                else -> {
                    val alg = when (oid) {
                        KnownOIDs.sha1WithRSAEncryption -> UNOFFICIAL_RSA_SHA1
                        KnownOIDs.sha256WithRSAEncryption -> RS256
                        KnownOIDs.sha384WithRSAEncryption -> RS384
                        KnownOIDs.sha512WithRSAEncryption -> RS512
                        else -> TODO("Implement remaining algorithm oid: $oid")
                    }
                    if (input.nextChild().tag != BERTags.NULL) throw IllegalArgumentException("RSA Params not supported yet")
                    if (input.hasMoreChildren()) throw IllegalArgumentException("Superfluous Content in Signature")
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