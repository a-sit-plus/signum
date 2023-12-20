package at.asitplus.crypto.datatypes.jws

import at.asitplus.crypto.datatypes.CryptoAlgorithm
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
enum class JwsAlgorithm(val identifier: String, override val oid: ObjectIdentifier) :
    Asn1Encodable<Asn1Sequence>,
    Identifiable {

    ES256("ES256", KnownOIDs.ecdsaWithSHA256),
    ES384("ES384", KnownOIDs.ecdsaWithSHA384),
    ES512("ES512", KnownOIDs.ecdsaWithSHA512),

    HS256("HS256", KnownOIDs.hmacWithSHA256),
    HS384("HS384", KnownOIDs.hmacWithSHA384),
    HS512("HS512", KnownOIDs.hmacWithSHA512),

    PS256("PS256", KnownOIDs.rsaPSS),
    PS384("PS384", KnownOIDs.rsaPSS),
    PS512("PS512", KnownOIDs.rsaPSS),

    RS256("RS256", KnownOIDs.sha256WithRSAEncryption),
    RS384("RS384", KnownOIDs.sha384WithRSAEncryption),
    RS512("RS512", KnownOIDs.sha512WithRSAEncryption),

    /**
     * The one exception, which is not a valid JWS algorithm identifier
     */
    NON_JWS_SHA1_WITH_RSA("RS1", KnownOIDs.sha1WithRSAEncryption);

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

    private fun encodePSSParams(bits: Int): Asn1Sequence {
        val shaOid = when (bits) {
            256 -> KnownOIDs.`sha-256`
            384 -> KnownOIDs.`sha-384`
            512 -> KnownOIDs.`sha-512`
            else -> TODO()
        }
        return asn1Sequence {
            append(oid)
            sequence {
                tagged(0.toUByte()) {
                    sequence {
                        append(shaOid)
                        asn1null()
                    }
                }
                tagged(1.toUByte()) {
                    sequence {
                        append(KnownOIDs.`pkcs1-MGF`)
                        sequence {
                            append(shaOid)
                            asn1null()
                        }
                    }
                }
                tagged(2.toUByte()) {
                    int(bits / 8)
                }
            }
        }
    }

    override fun encodeToTlv() = when (this) {
        ES256, ES384, ES512 -> asn1Sequence { append(oid) }

        PS256 -> encodePSSParams(256)

        PS384 -> encodePSSParams(384)

        PS512 -> encodePSSParams(512)

        HS256, HS384, HS512,
        RS256, RS384, RS512, NON_JWS_SHA1_WITH_RSA,
        -> asn1Sequence {
            append(oid)
            asn1null()
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, JwsAlgorithm> {

        @Throws(Asn1OidException::class)
        private fun fromOid(oid: ObjectIdentifier) = runCatching { entries.first { it.oid == oid } }.getOrElse {
            throw Asn1OidException("Unsupported OID: $oid", oid)
        }

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): JwsAlgorithm = runRethrowing {
            when (val oid = (src.nextChild() as Asn1Primitive).readOid()) {
                ES512.oid, ES384.oid, ES256.oid -> fromOid(oid)

                NON_JWS_SHA1_WITH_RSA.oid -> NON_JWS_SHA1_WITH_RSA
                RS256.oid, RS384.oid, RS512.oid,
                HS256.oid, HS384.oid, HS512.oid,
                -> fromOid(oid).also {
                    val tag = src.nextChild().tag
                    if (tag != BERTags.NULL)
                        throw Asn1TagMismatchException(BERTags.NULL, tag, "RSA Params not allowed.")
                }

                PS256.oid, PS384.oid, PS512.oid -> parsePssParams(src)
                else -> throw Asn1Exception("Unsupported algorithm oid: $oid")
            }
        }

        @Throws(Asn1Exception::class)
        private fun parsePssParams(src: Asn1Sequence): JwsAlgorithm = runRethrowing {
            val seq = src.nextChild() as Asn1Sequence
            val first = (seq.nextChild() as Asn1Tagged).verifyTag(0.toUByte()).single() as Asn1Sequence

            val sigAlg = (first.nextChild() as Asn1Primitive).readOid()
            val tag = first.nextChild().tag
            if (tag != BERTags.NULL)
                throw Asn1TagMismatchException(BERTags.NULL, tag, "PSS Params not supported yet")

            val second = (seq.nextChild() as Asn1Tagged).verifyTag(1.toUByte()).single() as Asn1Sequence
            val mgf = (second.nextChild() as Asn1Primitive).readOid()
            if (mgf != KnownOIDs.`pkcs1-MGF`) throw IllegalArgumentException("Illegal OID: $mgf")
            val inner = second.nextChild() as Asn1Sequence
            val innerHash = (inner.nextChild() as Asn1Primitive).readOid()
            if (innerHash != sigAlg) throw IllegalArgumentException("HashFunction mismatch! Expected: $sigAlg, is: $innerHash")

            if (inner.nextChild().tag != BERTags.NULL) throw IllegalArgumentException(
                "PSS Params not supported yet"
            )


            val last = (seq.nextChild() as Asn1Tagged).verifyTag(2.toUByte()).single() as Asn1Primitive
            val saltLen = last.readInt()


            return sigAlg.let {
                when (it) {
                    KnownOIDs.`sha-256` -> PS256.also { if (saltLen != 256 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }
                    KnownOIDs.`sha-384` -> PS384.also { if (saltLen != 384 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }
                    KnownOIDs.`sha-512` -> PS512.also { if (saltLen != 512 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }

                    else -> throw IllegalArgumentException("Unsupported OID: $it")
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